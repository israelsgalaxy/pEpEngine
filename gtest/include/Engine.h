#ifndef ENGINE_TEST_SUITE_H
#define ENGINE_TEST_SUITE_H

#include <string>
#include <map>
#include <vector>
#include <utility>
#include "pEpEngine.h"

using namespace std;

class Engine {
    public:
        Engine(string engine_home_dir);
        virtual ~Engine();
        
        void prep(messageToSend_t mts, inject_sync_event_t ise, std::vector<std::pair<std::string, std::string>> init_files);
        void start();
        void shut_down();
        
    protected:
        PEP_SESSION session;
        string engine_home;
        string real_home;
        string prev_pgp_home;
        
        messageToSend_t cached_messageToSend;
        inject_sync_event_t cached_inject_sync_event;
        	
        void copy_conf_file_to_test_dir(const char* dest_path, const char* conf_orig_path, const char* conf_dest_name);        
        void process_file_queue(std::string dirname, std::vector<std::pair<std::string, std::string>> file_queue);
};
#endif
