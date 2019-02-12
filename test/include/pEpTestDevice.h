#ifndef PEP_TEST_DEVICE_H
#define PEP_TEST_DEVICE_H

#include <cpptest.h>
#include <string>
#include <map>
#include <vector>
#include <utility>
#include "pEpEngine.h"

using namespace std;

class pEpTestDevice {
    public:
        pEpTestDevice(string test_dir, string my_name,
                      messageToSend_t mess_send_func = NULL,
                      inject_sync_event_t inject_sync_ev_func = NULL);        
                      
        virtual ~pEpTestDevice();
        string device_name;
        PEP_SESSION session;

        messageToSend_t device_messageToSend;
        inject_sync_event_t device_inject_sync_event;
        
    protected:
        string device_dir;        
        string root_test_dir;
        
//        string current_test_name;

        void set_device_environment();
        void teardown_device_environment();
        void grab_context();
        
//        void set_full_env();
//        void set_full_env(const char* gpg_conf_copy_path, const char* gpg_agent_conf_file_copy_path, const char* db_conf_file_copy_path);
//        void restore_full_env();
//        void initialise_test_home();
	
        // std::vector<std::pair<std::string, std::string>> gpgdir_fileadd_queue;
        // std::vector<std::pair<std::string, std::string>> homedir_fileadd_queue;
        // void add_file_to_gpg_dir_queue(std::string copy_from, std::string dst_fname);    
        // void add_file_to_home_dir_queue(std::string copy_from, std::string dst_fname);
        // void process_file_queue(std::string dirname, std::vector<std::pair<std::string, std::string>> file_queue);

};

#endif
