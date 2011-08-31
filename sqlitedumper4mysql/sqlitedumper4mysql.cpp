// sqlitedumper4mysql.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "sqlite3/sqlite3.h"

using namespace std;
namespace po = boost::program_options;

#if defined(_WIN32) || defined(WIN32)
# include <io.h>
#define isatty(h) _isatty(h)
#define access(f,m) _access((f),(m))
#else
/* Make sure isatty() has a prototype.
*/
extern int isatty();
#endif

/*
** Used to prevent warnings about unused parameters
*/
#define UNUSED_PARAMETER(x) (void)(x)

/*
** If the following flag is set, then command execution stops
** at an error if we are not interactive.
*/
static int bail_on_error = 0;

/*
** Threat stdin as an interactive input if the following variable
** is true.  Otherwise, assume stdin is connected to a file or pipe.
*/
static int stdin_is_interactive = 1;

/*
** The following is the open SQLite database.  We make a pointer
** to this database a static variable so that it can be accessed
** by the SIGINT handler to interrupt database processing.
*/
static sqlite3 *db = 0;

/*
** Prompt strings. Initialized in main. Settable with
**   .prompt main continue
*/
static char mainPrompt[20];     /* First line prompt. default: "sqlite> "*/
static char continuePrompt[20]; /* Continuation prompt. default: "   ...> " */

/*
** A global char* and an SQL function to access its current value 
** from within an SQL statement. This program used to use the 
** sqlite_exec_printf() API to substitue a string into an SQL statement.
** The correct way to do this with sqlite3 is to use the bind API, but
** since the shell is built around the callback paradigm it would be a lot
** of work. Instead just use this hack, which is quite harmless.
*/
static const char *zShellStatic = 0;
static void shellstaticFunc(
  sqlite3_context *context,
  int argc,
  sqlite3_value **argv
){
  assert( 0==argc );
  assert( zShellStatic );
  UNUSED_PARAMETER(argc);
  UNUSED_PARAMETER(argv);
  sqlite3_result_text(context, zShellStatic, -1, SQLITE_STATIC);
}


struct previous_mode_data {
  int valid;        /* Is there legit data in here? */
  int mode;
  int showHeader;
  int colWidth[100];
};

/*
** An pointer to an instance of this structure is passed from
** the main program to the callback.  This is used to communicate
** state and mode information.
*/
struct callback_data {
  sqlite3 *db;           /* The database */
  int echoOn;            /* True to echo input commands */
  int statsOn;           /* True to display memory stats before each finalize */
  int cnt;               /* Number of records displayed so far */
  FILE *out;             /* Write results here */
  int mode;              /* An output mode setting */
  int writableSchema;    /* True if PRAGMA writable_schema=ON */
  int showHeader;        /* True to show column names in List or Column mode */
  char *zDestTable;      /* Name of destination table when MODE_Insert */
  char separator[20];    /* Separator character for MODE_List */
  int colWidth[100];     /* Requested width of each column when in column mode*/
  int actualWidth[100];  /* Actual width of each column */
  char nullvalue[20];    /* The text to print when a NULL comes back from
                         ** the database */
  struct previous_mode_data explainPrev;
                         /* Holds the mode information just before
                         ** .explain ON */
  char outfile[FILENAME_MAX]; /* Filename for *out */
  const char *zDbFilename;    /* name of the database file */
  const char *zVfs;           /* Name of VFS to use */
  sqlite3_stmt *pStmt;   /* Current statement if any. */
  FILE *pLog;            /* Write log output here */
};

/*
** These are the allowed modes.
*/
#define MODE_List     2  /* One record per line with a separator */

/*
** Number of elements in an array
*/
#define ArraySize(X)  (int)(sizeof(X)/sizeof(X[0]))

/*
** Compute a string length that is limited to what can be stored in
** lower 30 bits of a 32-bit signed integer.
*/
static int strlen30(const char *z){
  const char *z2 = z;
  while( *z2 ){ z2++; }
  return 0x3fffffff & (int)(z2 - z);
}

/*
** A callback for the sqlite3_log() interface.
*/
static void shellLog(void *pArg, int iErrCode, const char *zMsg){
  struct callback_data *p = (struct callback_data*)pArg;
  if( p->pLog==0 ) return;
  fprintf(p->pLog, "(%d) %s\n", iErrCode, zMsg);
  fflush(p->pLog);
}

/*
** Set the destination table field of the callback_data structure to
** the name of the table given.  Escape any quote characters in the
** table name.
*/
static void set_table_name(struct callback_data *p, const char *zName){
  int i, n;
  int needQuote;
  char *z;

  if( p->zDestTable ){
    free(p->zDestTable);
    p->zDestTable = 0;
  }
  if( zName==0 ) return;
  needQuote = !isalpha((unsigned char)*zName) && *zName!='_';
  for(i=n=0; zName[i]; i++, n++){
    if( !isalnum((unsigned char)zName[i]) && zName[i]!='_' ){
      needQuote = 1;
      if( zName[i]=='\'' ) n++;
    }
  }
  if( needQuote ) n += 2;
  z = p->zDestTable = (char*)malloc( n+1 );
  if( z==0 ){
    fprintf(stderr,"Error: out of memory\n");
    exit(1);
  }
  n = 0;
  if( needQuote ) z[n++] = '\'';
  for(i=0; zName[i]; i++){
    z[n++] = zName[i];
    if( zName[i]=='\'' ) z[n++] = '\'';
  }
  if( needQuote ) z[n++] = '\'';
  z[n] = 0;
}

/* zIn is either a pointer to a NULL-terminated string in memory obtained
** from malloc(), or a NULL pointer. The string pointed to by zAppend is
** added to zIn, and the result returned in memory obtained from malloc().
** zIn, if it was not NULL, is freed.
**
** If the third argument, quote, is not '\0', then it is used as a 
** quote character for zAppend.
*/
static char *appendText(char *zIn, char const *zAppend, char quote){
  int len;
  int i;
  int nAppend = strlen30(zAppend);
  int nIn = (zIn?strlen30(zIn):0);

  len = nAppend+nIn+1;
  if( quote ){
    len += 2;
    for(i=0; i<nAppend; i++){
      if( zAppend[i]==quote ) len++;
    }
  }

  zIn = (char *)realloc(zIn, len);
  if( !zIn ){
    return 0;
  }

  if( quote ){
    char *zCsr = &zIn[nIn];
    *zCsr++ = quote;
    for(i=0; i<nAppend; i++){
      *zCsr++ = zAppend[i];
      if( zAppend[i]==quote ) *zCsr++ = quote;
    }
    *zCsr++ = quote;
    *zCsr++ = '\0';
    assert( (zCsr-zIn)==len );
  }else{
    memcpy(&zIn[nIn], zAppend, nAppend);
    zIn[len-1] = '\0';
  }

  return zIn;
}


/*
** Execute a query statement that has a single result column.  Print
** that result column on a line by itself with a semicolon terminator.
**
** This is used, for example, to show the schema of the database by
** querying the SQLITE_MASTER table.
*/
static int run_table_dump_query(
  FILE *out,              /* Send output here */
  sqlite3 *db,            /* Database to query */
  const char *zSelect,    /* SELECT statement to extract content */
  const char *zFirstRow   /* Print before first row, if not NULL */
){
  sqlite3_stmt *pSelect;
  int rc;

  const unsigned char* zIgnoreColumnText = (unsigned char*)"CREATE UNIQUE";

  rc = sqlite3_prepare(db, zSelect, -1, &pSelect, 0);
  if( rc!=SQLITE_OK || !pSelect ){
    return rc;
  }
  rc = sqlite3_step(pSelect);
  while( rc==SQLITE_ROW ){
    if( zFirstRow ){
      fprintf(out, "%s", zFirstRow);
      zFirstRow = 0;
    }
    
    const unsigned char *zColumnText = sqlite3_column_text(pSelect, 0);

    // for MySQL dump;
    // if (_mbsncmp(zColumnText, zIgnoreColumnText, _mbslen(zIgnoreColumnText)) != 0)
    if (strncmp((char*)zColumnText, (char*)zIgnoreColumnText, strlen((char*)zIgnoreColumnText)) != 0)
      fprintf(out, "%s;\n", zColumnText);

    rc = sqlite3_step(pSelect);
  }
  return sqlite3_finalize(pSelect);
}

/*
** This is a different callback routine used for dumping the database.
** Each row received by this callback consists of a table name,
** the table type ("index" or "table") and SQL to create the table.
** This routine should print text sufficient to recreate the table.
*/
static int dump_callback(void *pArg, int nArg, char **azArg, char **azCol){
  int rc;
  const char *zTable;
  const char *zType;
  const char *zSql;
  const char *zPrepStmt = 0;
  struct callback_data *p = (struct callback_data *)pArg;

  UNUSED_PARAMETER(azCol);
  if( nArg!=3 ) return 1;
  zTable = azArg[0];
  zType = azArg[1];
  zSql = azArg[2];
  
  if( strcmp(zTable, "sqlite_sequence")==0 ){
    zPrepStmt = "DELETE FROM sqlite_sequence;\n";
  }else if( strcmp(zTable, "sqlite_stat1")==0 ){
    fprintf(p->out, "ANALYZE sqlite_master;\n");
  }else if( strncmp(zTable, "sqlite_", 7)==0 ){
    return 0;
  }else if( strncmp(zSql, "CREATE VIRTUAL TABLE", 20)==0 ){
    char *zIns;
    if( !p->writableSchema ){
      fprintf(p->out, "PRAGMA writable_schema=ON;\n");
      p->writableSchema = 1;
    }
    zIns = sqlite3_mprintf(
       "INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql)"
       "VALUES('table','%q','%q',0,'%q');",
       zTable, zTable, zSql);
    fprintf(p->out, "%s\n", zIns);
    sqlite3_free(zIns);
    return 0;
  }else{
    fprintf(p->out, "%s;\n", zSql);
  }

  if( strcmp(zType, "table")==0 ){
    sqlite3_stmt *pTableInfo = 0;
    char *zSelect = 0;
    char *zTableInfo = 0;
    char *zTmp = 0;
    int nRow = 0;
   
    zTableInfo = appendText(zTableInfo, "PRAGMA table_info(", 0);
    zTableInfo = appendText(zTableInfo, zTable, '"');
    zTableInfo = appendText(zTableInfo, ");", 0);

    rc = sqlite3_prepare(p->db, zTableInfo, -1, &pTableInfo, 0);
    free(zTableInfo);
    if( rc!=SQLITE_OK || !pTableInfo ){
      return 1;
    }

    zSelect = appendText(zSelect, "SELECT 'INSERT INTO ' || ", 0);
    //zTmp = appendText(zTmp, zTable, '"');
    zTmp = appendText(zTmp, zTable, '`'); // for compatible MySQL
    if( zTmp ){
      zSelect = appendText(zSelect, zTmp, '\'');
    }
    zSelect = appendText(zSelect, " || ' VALUES(' || ", 0);
    rc = sqlite3_step(pTableInfo);
    while( rc==SQLITE_ROW ){
      const char *zText = (const char *)sqlite3_column_text(pTableInfo, 1);
      zSelect = appendText(zSelect, "quote(", 0);
      zSelect = appendText(zSelect, zText, '"');
      rc = sqlite3_step(pTableInfo);
      if( rc==SQLITE_ROW ){
        zSelect = appendText(zSelect, ") || ',' || ", 0);
      }else{
        zSelect = appendText(zSelect, ") ", 0);
      }
      nRow++;
    }
    rc = sqlite3_finalize(pTableInfo);
    if( rc!=SQLITE_OK || nRow==0 ){
      free(zSelect);
      return 1;
    }
    zSelect = appendText(zSelect, "|| ')' FROM  ", 0);
    zSelect = appendText(zSelect, zTable, '"');

    rc = run_table_dump_query(p->out, p->db, zSelect, zPrepStmt);
    if( rc==SQLITE_CORRUPT ){
      zSelect = appendText(zSelect, " ORDER BY rowid DESC", 0);
      rc = run_table_dump_query(p->out, p->db, zSelect, 0);
    }
    if( zSelect ) free(zSelect);
  }
  return 0;
}

/*
** Run zQuery.  Use dump_callback() as the callback routine so that
** the contents of the query are output as SQL statements.
**
** If we get a SQLITE_CORRUPT error, rerun the query after appending
** "ORDER BY rowid DESC" to the end.
*/
static int run_schema_dump_query(
  struct callback_data *p, 
  const char *zQuery,
  char **pzErrMsg
){
  int rc;
  rc = sqlite3_exec(p->db, zQuery, dump_callback, p, pzErrMsg);
  if( rc==SQLITE_CORRUPT ){
    char *zQ2;
    int len = strlen30(zQuery);
    if( pzErrMsg ) sqlite3_free(*pzErrMsg);
    zQ2 = (char*)malloc( len+100 );
    if( zQ2==0 ) return rc;
    sqlite3_snprintf(sizeof(zQ2), zQ2, "%s ORDER BY rowid DESC", zQuery);
    rc = sqlite3_exec(p->db, zQ2, dump_callback, p, pzErrMsg);
    free(zQ2);
  }
  return rc;
}

/*
** Make sure the database is open.  If it is not, then open it.  If
** the database fails to open, print an error message and exit.
*/
static void open_db(struct callback_data *p){
  if( p->db==0 ){
    sqlite3_open(p->zDbFilename, &p->db);
    db = p->db;
    if( db && sqlite3_errcode(db)==SQLITE_OK ){
      sqlite3_create_function(db, "shellstatic", 0, SQLITE_UTF8, 0,
          shellstaticFunc, 0, 0);
    }
    if( db==0 || SQLITE_OK!=sqlite3_errcode(db) ){
      fprintf(stderr,"Error: unable to open database \"%s\": %s\n", 
          p->zDbFilename, sqlite3_errmsg(db));
      exit(1);
    }
#ifndef SQLITE_OMIT_LOAD_EXTENSION
    sqlite3_enable_load_extension(p->db, 1);
#endif
  }
}

static int do_dump(const char* zDumpPath, struct callback_data *p) {
  int rc = 0;

  p->out = fopen(zDumpPath, "wb");
  open_db(p);
  /* When playing back a "dump", the content might appear in an order
  ** which causes immediate foreign key constraints to be violated.
  ** So disable foreign-key constraint enforcement to prevent problems. */
  //    fprintf(p->out, "PRAGMA foreign_keys=OFF;\n");
  //    fprintf(p->out, "BEGIN TRANSACTION;\n");
  p->writableSchema = 0;
  sqlite3_exec(p->db, "PRAGMA writable_schema=ON", 0, 0, 0);
  run_schema_dump_query(p, 
    "SELECT name, type, sql FROM sqlite_master "
    "WHERE sql NOT NULL AND type=='table' AND name!='sqlite_sequence'", 0
    );
  run_schema_dump_query(p, 
    "SELECT name, type, sql FROM sqlite_master "
    "WHERE name=='sqlite_sequence'", 0
    );
  // 이 부분은 sqlite db 파일에 이미 존재하는 INDEX 생성 관련 문장을 가져옴.
  run_table_dump_query(p->out, p->db,
    "SELECT sql FROM sqlite_master "
    "WHERE sql NOT NULL AND type IN ('index','trigger','view')", 0
    );

  if( p->writableSchema ){
    fprintf(p->out, "PRAGMA writable_schema=OFF;\n");
    p->writableSchema = 0;
  }
  sqlite3_exec(p->db, "PRAGMA writable_schema=OFF", 0, 0, 0);
//  fprintf(p->out, "COMMIT;\n");

  return rc;
}

/*
** Initialize the state information in data
*/
static void main_init(struct callback_data *data) {
  memset(data, 0, sizeof(*data));
  data->mode = MODE_List;
  memcpy(data->separator,"|", 2);
  data->showHeader = 0;
  sqlite3_config(SQLITE_CONFIG_URI, 1);
  sqlite3_config(SQLITE_CONFIG_LOG, shellLog, data);
  sqlite3_snprintf(sizeof(mainPrompt), mainPrompt,"sqlite> ");
  sqlite3_snprintf(sizeof(continuePrompt), continuePrompt,"   ...> ");
  sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
}

void printHelp(const string& strMsg)
{
  MessageBoxA(NULL, strMsg.c_str(), "Help", MB_OK | MB_ICONERROR);
}

int main(int argc, char* argv[])
{
  string inputSrcDBPath;
  string inputDestFilePath;

  try
  {
    po::options_description desc("Allowed options");
    po::positional_options_description p;
    // p.add("files", -1 )은 기본 옵션 -아무런 옵션 이름을 안주고 인자를 주면 
    // 그거에 대한 인자를 준걸로 받아들임-
    p.add("source", -1);
    /* 옵션 세팅 및 값 받아오는 변수 설정 */
    desc.add_options()
      ("help,h", "produce a help message")
      ("source,s", po::value<string>(&inputSrcDBPath), "source file path")
      ("destination,d", po::value<string>(&inputDestFilePath), "destination file path");

    po::variables_map vm;
    po::store(
      po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
    po::notify(vm);
    if ( vm.count("help") || !vm.count("source") || !vm.count("destination")) {
      std::stringstream str;
      str << desc;
      printHelp(str.str());
      return 0;
    }
  }
  catch ( std::exception& e )
  {
    cout << "Error: " << e.what() << endl;
    return 1;
  }
  catch ( ... )
  {
    cout << "Error: Unknown error" << endl;
    return 1;
  } 

  //////////////////////////////////////////////////////////////////////////

  char* zErrMsg = 0;
  struct callback_data data;
  const char* zInitFile = 0;
  int rc = 0;

  if( strcmp(sqlite3_sourceid(),SQLITE_SOURCE_ID)!=0 ){
    fprintf(stderr, "SQLite header and source version mismatch\n%s\n%s\n",
            sqlite3_sourceid(), SQLITE_SOURCE_ID);
    exit(1);
  }

  main_init(&data);
  stdin_is_interactive = isatty(0);

  data.zDbFilename = inputSrcDBPath.c_str();

  /* Go ahead and open the database file if it already exists.  If the
  ** file does not exist, delay opening it.  This prevents empty database
  ** files from being created if a user mistypes the database name argument
  ** to the sqlite command-line tool.
  */
  if( access(data.zDbFilename, 0)==0 ){
    open_db(&data);
  }

  /* Make a second pass through the command-line argument and set
  ** options.  This second pass is delayed until after the initialization
  ** file is processed so that the command-line arguments will override
  ** settings in the initialization file.
  */

  string destDumpFilePath;
  if (inputDestFilePath.empty())
    destDumpFilePath = "";
  else
    destDumpFilePath = inputDestFilePath;

  rc = do_dump(destDumpFilePath.c_str(), &data);
  set_table_name(&data, 0);
  if( data.db ){
    sqlite3_close(data.db);
  }

  return rc;
}