#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>
#include <assert.h>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>

#include <string>
#include <vector>
#include <utility>

#include "platform_unix.h"

#include "TestUtilities.h"
#include "Engine.h"
#include "pEpTestStatic.h"
#include "pEpEngine_internal.h"

#include <algorithm>
#include "TestConstants.h"

using namespace std;

// #define DEBUG_PATH_CACHE

#if defined(DEBUG_PATH_CACHE)
# define LOG(...)                 \
    do {                          \
        FILE *f = stdout;         \
        fprintf(f, __VA_ARGS__);  \
        fflush(f);                \
    } while (false)
#else
# define LOG(...) do {} while (false)
#endif

pthread_mutex_t the_mutex
#if defined(GNULINUX)
= PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#else
= PTHREAD_RECURSIVE_MUTEX_INITIALIZER;
#endif

// Constructor
Engine::Engine(string engine_home_dir) {
    // FIXME: deal with base
    engine_home = engine_home_dir;
            
    real_home = getenv("HOME");
    cached_messageToSend = NULL;
    cached_inject_sync_event = NULL;
    cached_ensure_passphrase = NULL;

    /* Make sure we correctly initialise the path cache.  This is needed so that
       we can avoid concurrency problems between the global path cache and
       Engine initialisation.
       This ugly trick is not necessary in applications and adapters which
       initialise the Engine correctly, by first calling init in a single
       thread; but this test suite does not respect such conventions. */
    pthread_mutex_lock(& the_mutex);
    LOG("Initialise path cache: begin\n");
    const char *useless __attribute__((unused));
    useless = per_user_relative_directory();
    useless = per_user_directory();
    useless = per_machine_directory();
#ifdef ANDROID
    useless = android_system_db();
#endif
    useless = unix_system_db();
    useless = unix_local_db();
    useless = unix_log_db();
    LOG("Initialise path cache: end\n");
    pthread_mutex_unlock(& the_mutex);
}

Engine::~Engine() {}

void Engine::prep(messageToSend_t mts, inject_sync_event_t ise, ensure_passphrase_t ep,
                  std::vector<std::pair<std::string, std::string>> init_files) {
    if (engine_home.empty())
        throw std::runtime_error("Engine setup: BAD INITIALISATION. No test home.");
    
    cached_messageToSend = mts;
    cached_inject_sync_event = ise;
    cached_ensure_passphrase = ep;

    int success = 0;
    struct stat dirchk;
        
    if (stat(engine_home.c_str(), &dirchk) == 0) {
        if (!S_ISDIR(dirchk.st_mode))
            throw std::runtime_error(("ENGINE SETUP: The test directory, " + engine_home + " exists, but is not a directory.").c_str()); 
                    
        struct stat buf;

        if (stat(engine_home.c_str(), &buf) == 0) {
            int success = nftw((engine_home + "/.").c_str(), util_delete_filepath, 100, FTW_DEPTH);
        }
    }
    else {
        // Look, we're not creating all of these dirs...
        const int errchk = system((string("mkdir -p ") + engine_home).c_str());
        if (errchk != 0)
            throw std::runtime_error("ENGINE SETUP: Error creating a test directory.");        
    }

    process_file_queue(engine_home, init_files);

    // We will set homedirs etc outside this function. Right now, we're just making sure we can.
    // Let's make sure we're not trying to run it under the real current home, however.
    
    if (engine_home.compare(real_home) == 0 || engine_home.compare(real_home + "/") == 0)
        throw std::runtime_error("ENGINE SETUP: Cowardly refusing to set up for playing in what looks like the real home directory.");
    
}

void Engine::start() {    
    if (engine_home.empty())
        throw std::runtime_error("Engine start: BAD INITIALISATION. No test home. Did you call Engine::prep() first?");

    assert(engine_home.compare(real_home) != 0);
    assert(engine_home.compare(real_home + "/") != 0);
    output_stream << "Test home directory is " << engine_home << endl;
    
    int success = 0;
        
    success = setenv("HOME", engine_home.c_str(), 1);
    if (success != 0)
        throw std::runtime_error("SETUP: Cannot set engine_home for init.");
            
    PEP_STATUS status;
    status = reset_path_cache();
    assert(status == PEP_STATUS_OK);

    status = init(&session, cached_messageToSend, cached_inject_sync_event, cached_ensure_passphrase);
    assert(status == PEP_STATUS_OK);
    assert(session);
}

void Engine::copy_conf_file_to_test_dir(const char* dest_path, const char* conf_orig_path, const char* conf_dest_name) {
    string conf_dest_path
      = (string(dest_path)
         + string("/")
         + string(per_user_relative_directory ())
         + string("/"));
fprintf (stderr, "COPYING %s from %s to %s\n",
         dest_path,
         conf_orig_path,
         conf_dest_path.c_str ());
    struct stat pathinfo;

    if(stat(conf_dest_path.c_str(), &pathinfo) != 0) {
        int errchk = mkdir(conf_dest_path.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        if (errchk != 0)
            throw std::runtime_error("Error accessing conf file directory.");
    }
    
    conf_dest_path += "/";
    conf_dest_path += conf_dest_name;
    
    ifstream src(conf_orig_path);
    ofstream dst(conf_dest_path.c_str(), ios::trunc);
    
    assert(src);
    assert(dst);
    
    dst << src.rdbuf();
     
    src.close();
    dst.close();
}

void Engine::process_file_queue(string dirname, vector<pair<string, string>> file_queue) {
    if (file_queue.empty())
        return;
        
    vector<pair<string, string>>::iterator it;
    
    for (it = file_queue.begin(); it != file_queue.end(); it++) {
        copy_conf_file_to_test_dir(dirname.c_str(), it->first.c_str(), it->second.c_str());
    }
    
    file_queue.clear();
}

void Engine::shut_down() {
    release(session);
    session = NULL;
        
    int success = 0;    
                
    success = nftw((engine_home + "/.").c_str(), util_delete_filepath, 100, FTW_DEPTH);
    
    success = setenv("HOME", real_home.c_str(), 1);
    if (success != 0)
        throw std::runtime_error("RESTORE: Cannot reset home directory! Either set environment variable manually back to your home, or quit this session!");

    PEP_STATUS status = reset_path_cache();
    assert(status == PEP_STATUS_OK);
}
