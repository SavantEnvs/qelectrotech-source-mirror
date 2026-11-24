/*
	libFuzzer harness for QElectroTech's file readers, driven through the
	program's own headless command line (CLIExport::run, sources/cli_export.cpp),
	the same code `qelectrotech --resave/--info/--export-*` runs from main().

	One binary, several targets: the mode is picked from the program name
	(argv[0]) -- fuzz_qet_<mode> and fuzz_qet_<mode>-standalone are hard links
	to the same harness -- so every Mayhem target is a plain libFuzzer target.

	  resave   project XML (.qet)        --resave in.qet out.qet
	  qetz     zip+SQLite container      --info in.qetz out.json
	  recover  damaged container         --recover in.qetz out.qet
	  dxf      project + DXF writer      --export-dxf in.qet outdir --dxf-blocks --dxf-attributes
	  svg      project + painting        --export-svg in.qet outdir --show-terminals
	  nets     project + net analysis    --export-nets in.qet out.json
	  elmt     symbol definition (.elmt) --check-elements in.elmt --grid
	  qetdb    SQLite project (.qetdb)   --info in.qetdb out.json
	  edz      EPLAN part package (.edz) EdzArchive::extract -> EdzPart::parse
	                                     -> EdzElementBuilder::build/toElmtString
	           (the "Import an EPLAN part" pipeline of EdzImporter, minus the
	           final write of the .elmt; it has no command-line switch)

	edz: sevenZipExtract writes every archive entry to QDir::filePath(name)
	without checking that it stays inside the extraction folder, so an entry
	named "../x" or "/x" is written outside it (CWE-22, "zip slip"). No
	sanitizer sees that, and it would leave files behind between inputs, so
	the harness reads the entry names first with the same bundled LZMA SDK
	reader and aborts on one that escapes, before anything is extracted.

	State kept across inputs: the QApplication and the settings directory,
	both read-only for these modes. Each input is written to a fresh file in a
	private scratch directory under $TMPDIR, and every output is deleted after
	the run, so one input's result depends only on that input.
*/
#include <QApplication>
#include <QDir>
#include <QDomImplementation>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QStringList>
#include <QTemporaryDir>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "cli_export.h"
#include "import/edz/edzarchive.h"
#include "import/edz/edzelementbuilder.h"
#include "import/edz/edzpart.h"
#include "import/edz/lzma/7z.h"
#include "import/edz/lzma/7zAlloc.h"
#include "import/edz/lzma/7zCrc.h"
#include "import/edz/lzma/7zFile.h"
#include "import/edz/lzma/7zTypes.h"
#include "projectlock.h"
#include "qetmessagebox.h"
#include "qetproject.h"

namespace {

QApplication *g_app = nullptr;
QTemporaryDir *g_scratch = nullptr;
std::string g_mode;

void quietHandler(QtMsgType, const QMessageLogContext &, const QString &) {}

std::string modeFromArgv0(const char *argv0)
{
	std::string name = argv0 ? argv0 : "";
	const size_t slash = name.find_last_of('/');
	if (slash != std::string::npos) name = name.substr(slash + 1);
	const std::string standalone = "-standalone";
	if (name.size() > standalone.size()
		&& name.compare(name.size() - standalone.size(), standalone.size(), standalone) == 0)
		name.resize(name.size() - standalone.size());
	const std::string prefix = "fuzz_qet_";
	if (name.compare(0, prefix.size(), prefix) == 0) name = name.substr(prefix.size());
	return name;
}

/*
	The entry names of the 7-Zip archive at @a path, read the way
	sevenZipExtract (sources/import/edz/edzsevenzip.cpp) reads them; empty if
	the archive does not open.
*/
QStringList sevenZipEntryNames(const QString &path)
{
	QStringList names;
	ISzAlloc allocImp     = { SzAlloc, SzFree };
	ISzAlloc allocTempImp = { SzAllocTemp, SzFreeTemp };
	CFileInStream archiveStream;
	const QByteArray apath = QFile::encodeName(path);
	if (InFile_Open(&archiveStream.file, apath.constData()) != 0) return names;
	FileInStream_CreateVTable(&archiveStream);
	archiveStream.wres = 0;
	CLookToRead2 lookStream;
	LookToRead2_CreateVTable(&lookStream, 0);
	const size_t bufSize = (size_t)1 << 18;
	lookStream.buf = static_cast<Byte *>(ISzAlloc_Alloc(&allocImp, bufSize));
	if (lookStream.buf) {
		lookStream.bufSize = bufSize;
		lookStream.realStream = &archiveStream.vt;
		LookToRead2_INIT(&lookStream)
		CrcGenerateTable();
		CSzArEx db;
		SzArEx_Init(&db);
		if (SzArEx_Open(&db, &lookStream.vt, &allocImp, &allocTempImp) == SZ_OK) {
			std::vector<UInt16> name;
			for (UInt32 i = 0; i < db.NumFiles; ++i) {
				const size_t len = SzArEx_GetFileNameUtf16(&db, i, nullptr);
				name.assign(len ? len : 1, 0);
				SzArEx_GetFileNameUtf16(&db, i, name.data());
				names << QString::fromUtf16(reinterpret_cast<const char16_t *>(name.data()));
			}
		}
		SzArEx_Free(&db, &allocImp);
		ISzAlloc_Free(&allocImp, lookStream.buf);
	}
	File_Close(&archiveStream.file);
	return names;
}

void runEdz(const QString &in)
{
	for (QString rel : sevenZipEntryNames(in)) {
		rel.replace(QLatin1Char('\\'), QLatin1Char('/'));
		if (rel.isEmpty()) continue;
		if (QDir::isAbsolutePath(rel) || rel.split(QLatin1Char('/')).contains(QStringLiteral(".."))) {
			fprintf(stderr, "qet_cli_fuzzer: .edz entry '%s' would be extracted outside the "
				"extraction folder (path traversal in sevenZipExtract)\n", qPrintable(rel));
			abort();
		}
	}
	EdzArchive archive;
	if (!archive.extract(in)) return;
	EdzPart part;
	if (!part.parse(archive.partXmlPath())) return;
	const QString elmt = EdzElementBuilder::toElmtString(EdzElementBuilder::build(part));
	(void)elmt;
	// archive's destructor removes the extracted tree.
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	g_mode = modeFromArgv0(*argc > 0 ? (*argv)[0] : nullptr);
	if (const char *m = getenv("QET_FUZZ_MODE")) g_mode = m; // manual override
	static const char *known[] = {"resave", "qetz", "recover", "dxf", "svg", "nets", "elmt", "qetdb", "edz"};
	bool ok = false;
	for (const char *k : known) ok = ok || g_mode == k;
	if (!ok) {
		fprintf(stderr, "qet_cli_fuzzer: unknown mode '%s' (run as fuzz_qet_<mode>)\n", g_mode.c_str());
		abort();
	}

	qputenv("QT_QPA_PLATFORM", "offscreen");
	qputenv("QT_HASH_SEED", "0");
	QCoreApplication::setOrganizationName("QElectroTech");
	QCoreApplication::setOrganizationDomain("qelectrotech.org");
	QCoreApplication::setApplicationName("QElectroTech");

	static int app_argc = 1;
	static char app_name[] = "qelectrotech";
	static char *app_argv[] = {app_name, nullptr};

	// Settings go to a private INI folder, never $HOME (as main() does with
	// QET_SETTINGS_DIR).
	g_scratch = new QTemporaryDir(QDir::tempPath() + "/qet-fuzz-XXXXXX");
	if (!g_scratch->isValid()) abort();
	const QString settings_dir = g_scratch->filePath("settings");
	QDir().mkpath(settings_dir);
	QSettings::setDefaultFormat(QSettings::IniFormat);
	QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settings_dir);
	QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, settings_dir);
	QDomImplementation::setInvalidDataPolicy(QDomImplementation::ReturnNullNode);

	qInstallMessageHandler(quietHandler);
	g_app = new QApplication(app_argc, app_argv);
	// Same headless set-up as main() before CLIExport::run.
	QETProject::setBackupEnabled(false);
	ProjectLock::setHeadless(true);
	QET::QetMessageBox::setNonInteractive(true);
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	QTemporaryDir work(g_scratch->filePath("run-XXXXXX"));
	if (!work.isValid()) abort();

	QString ext = "qet";
	if (g_mode == "qetz" || g_mode == "recover") ext = "qetz";
	else if (g_mode == "elmt") ext = "elmt";
	else if (g_mode == "qetdb") ext = "qetdb";
	else if (g_mode == "edz") ext = "edz";

	const QString in = work.filePath("input." + ext);
	{
		QFile f(in);
		if (!f.open(QIODevice::WriteOnly)) abort();
		if (size && f.write(reinterpret_cast<const char *>(data), qint64(size)) != qint64(size)) abort();
	}
	if (g_mode == "edz") {
		runEdz(in);
		return 0;
	}
	const QString outdir = work.filePath("out");
	QDir().mkpath(outdir);

	QStringList args{"qelectrotech"};
	if (g_mode == "resave")
		args << "--resave" << in << work.filePath("out.qet") << "--ignore-lock";
	else if (g_mode == "qetz" || g_mode == "qetdb")
		args << "--info" << in << work.filePath("out.json") << "--ignore-lock";
	else if (g_mode == "recover")
		args << "--recover" << in << work.filePath("out.qet");
	else if (g_mode == "dxf")
		args << "--export-dxf" << in << outdir << "--dxf-blocks" << "--dxf-attributes" << "--ignore-lock";
	else if (g_mode == "svg")
		args << "--export-svg" << in << outdir << "--show-terminals" << "--ignore-lock";
	else if (g_mode == "nets")
		args << "--export-nets" << in << work.filePath("out.json") << "--ignore-lock";
	else if (g_mode == "elmt")
		args << "--check-elements" << in << "--grid";

	CLIExport::run(args);
	// work's destructor removes the input and every output.
	return 0;
}
