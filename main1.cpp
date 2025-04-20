/*
 * Copyright (c) 2016, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

 
#include <iostream>
#include <vector>
#include <tins/tins.h>
#include <fstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <string>
#include <filesystem>
using namespace Tins;
std::string port = "lo";
short lower_level_of_susp_detection = 3;
short upper_level_of_susp_detection = 7;
int edege_of_suspicion_payload_weight = 128;
int freqwency_of_analysing = 5000;
std::string help = "\ndo_report - create report wiht icmp dump \nshow_dump - print icmp dump\nexit - to exit \nhelp - to see all commands \nturn_on_devmod - to disable protection against incorrect user actions (unstable operation mode!!!) \nturn_off_devmod - to turn of developer mode \nchange_lower_level_of_susp_detection - to change lower level of suspicion detection (usage : change_lower_level_of_susp_detection <int_exempl_level>) \nsettings - to see all settings \nchange_upper_level_of_susp_detection - to change upper level of suspicion detection (usage : change_upper_level_of_susp_detection <int_exempl_level>) \nto cange port - restart programm \nchint - to change interval of analysing \nimpsettings - to import settings in pingspysettings.txt \nexpsettings - to export settings file\n  ";


std::ofstream fout ("otchet.txt");
void do_otchet (std::vector<Packet> vt){
    

    for (const auto& packet : vt) {
        // Is there an IP PDU somewhere?
        const ICMP& icmp = packet.pdu()->rfind_pdu<ICMP>();
        if (packet.pdu()->find_pdu<IP>()) {
            // Just print timestamp's seconds and IP source address
            fout << "At: " << packet.timestamp().seconds()
                    << " - " << packet.pdu()->rfind_pdu<IP>().src_addr()<<" to "
                    << packet.pdu()->rfind_pdu<IP>().dst_addr()
                    << std::endl;
        }
        const RawPDU& raw = icmp.rfind_pdu<RawPDU>();
        const RawPDU::payload_type& payload = raw.payload();
           
        fout<<"payload:"<<std::endl;
        for(const auto& b: payload ){
            fout << b;
        }
        fout <<std::endl;
    }
        std::cout <<"report has been created with name <otchet>";

}
void show_dump (std::vector<Packet> vt){
    
    if (vt.size()>0){
        for (const auto& packet : vt) {
            // Is there an IP PDU somewhere?
            const ICMP& icmp = packet.pdu()->rfind_pdu<ICMP>();
        
        
        
            // Just print timestamp's seconds and IP source address
            std::cout << "At: " << packet.timestamp().seconds()
                 << " - " << packet.pdu()->rfind_pdu<IP>().src_addr() 
                << std::endl; 
        
            const RawPDU& raw = icmp.rfind_pdu<RawPDU>();
            const RawPDU::payload_type& payload = raw.payload();
           
            std::cout<<"payload:"<<std::endl;
            for(uint8_t b: payload ){
                std::cout << b;
            }
            std::cout <<std::endl;
        }
    }else{
        std::cout <<"icmp dump is empty\n";
    }

}

const RawPDU::payload_type& get_payload(Packet packet){


    const ICMP& icmp = packet.pdu()->rfind_pdu<ICMP>();
    const RawPDU& raw = icmp.rfind_pdu<RawPDU>();
    const RawPDU::payload_type& payload = raw.payload();
    return  payload ;


}

void analyzing_f(std::vector<Packet> & vt){
    std::vector<Packet> vtan;
    int last_icmp_count = vt.size();
    int count_of_anomaly_packet=0;
    short int degree_of_suspicion=0; 
    int coutn_of_encapsulated_traffic=0; 
    std::string encapsuiated_protocol; 
    int it = 0;

    while (true){
        std::this_thread::sleep_for(std::chrono::milliseconds(freqwency_of_analysing));
        
        for (int i = it; i<vt.size();i++){
            vtan.push_back(vt[i]);
        }

        if (vtan.size()>0){


            



            for (auto i = vtan.begin()+it;i<vtan.end()-1;i++){
                
                

                if (get_payload(*i).size()>edege_of_suspicion_payload_weight){
                    count_of_anomaly_packet++;
                }

                

                if (get_payload(*i)[0] == 0 and get_payload(*i).size()>30){
                    
                    if (get_payload(*i)[23] == 1){
                        encapsuiated_protocol ="ICMP";
                        coutn_of_encapsulated_traffic++;
                    }
                    if (get_payload(*i)[23] == 17){
                        encapsuiated_protocol ="UDP";
                        coutn_of_encapsulated_traffic++;

                    }
                    if (get_payload(*i)[23] == 6){
                        encapsuiated_protocol ="TCP";
                        coutn_of_encapsulated_traffic++;
                    }
                }
            }
            
            if (vtan.size()-it){
                degree_of_suspicion +=3;
            }
            
        }
        degree_of_suspicion = degree_of_suspicion+count_of_anomaly_packet;
        if ((degree_of_suspicion > lower_level_of_susp_detection) and (degree_of_suspicion < upper_level_of_susp_detection) ){
            std::cout<<"suspicious icmp activity was detected"<<std::endl
            <<"suspicious level:"<< degree_of_suspicion<<std::endl<<std::endl;
        }
        if (degree_of_suspicion > upper_level_of_susp_detection   ){
            std::cout<<"Extremely suspicious icmp activity has been detected."<<std::endl
            <<"We recommmend run an antivirus software chreck."<<std::endl
            <<"suspicious level: "<< degree_of_suspicion<<std::endl<<std::endl;
        }
        if (coutn_of_encapsulated_traffic>1){
            std::cout<<"ICMP tunnel has been detected."<<std::endl
            <<"We recommmend run an antivirus software chreck."<<std::endl
            <<"encapsulated protocol is: "<< encapsuiated_protocol<<std::endl<<std::endl;
        }
        
        it =vtan.size();
        degree_of_suspicion =0;
        coutn_of_encapsulated_traffic =0;
        count_of_anomaly_packet = 0;
    }
}

void snifing_treade (std::vector<Packet> & vt, std::string port){
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniffer(port,config);
    sniffer.set_filter("icmp");
    while (true){
        vt.push_back(sniffer.next_packet());
    }
} 

std::vector<std::string>  get_ports_names (){
    std::vector <NetworkInterface> interfases = NetworkInterface::all();
    std::vector <std::string> names_of_interfases ;
    for (int i =0 ;i<interfases.size();i++){
        names_of_interfases.push_back(interfases[i].name());
    }
    return names_of_interfases;
}

void print_list (std::vector<std::string> main_list){
    for (int i =0;i<main_list.size();i++){
        std::cout<<main_list[i]<<std::endl;
    }
}

void make_impression_of_settings(){
    std::ofstream fout1 ("pingspysettings.txt");
    fout1<<port<<" "<<lower_level_of_susp_detection <<" "<<upper_level_of_susp_detection <<" "<< edege_of_suspicion_payload_weight <<" "<< freqwency_of_analysing;
}
void reed_settings (){
    std::ifstream fin1 ("pingspysettings.txt");
    if(fin1.is_open()){
    fin1>>port>>lower_level_of_susp_detection >>upper_level_of_susp_detection >> edege_of_suspicion_payload_weight >> freqwency_of_analysing;
    }else {
        std::cout<<"no settings file\n";
    }
}
int main() {

    std::string invalid_value_error = "Invalid value. Try again with a differend value or turn on dev mod\n";

    std::vector<std::string>  ports_name = get_ports_names();

    std::cout<<"plise select port from list \n";
    print_list (ports_name);
    
    port = "eth0";
    std::string temp_string;
    while (true){
        std::cin >> temp_string;
        if (std::count(ports_name.begin(),ports_name.end(),temp_string)!=0){
            port = temp_string;
            break;
        }else{
            std::cout << "non-existent port"<<std::endl;
        }
    }
    
    if (std::filesystem::exists("pingspysettings.txt")){
        reed_settings();
    }

    bool dev_mode = true;
    std::vector<Packet> vt;
    std::thread snifing(snifing_treade,std::ref(vt),port);
    snifing.detach();
    std::thread analyzing (analyzing_f,std::ref(vt));
    analyzing.detach();
    std::string command = "defolt_command";
    std::cout <<"exit - to exit"<<std::endl<<"help - to see all commands"<<std::endl;
    while (command != "exit"){
        std::cin>>command;
        if (command == "do_report"){
            do_otchet(vt);
        }
        if (command == "show_dump"){
            show_dump(vt);
        }
        if (command == "help" ){
            std::cout << help<<std::endl;
        }
        if ((command == "change_lower_level_of_susp_detection") ){
            short temp = 0;
            std::cin >> temp;
            if ((temp < 100) and (temp>0) or dev_mode ){
                lower_level_of_susp_detection = temp; 
            }
            else{
                std::cout<<invalid_value_error;
            }
            temp = 0;
        }
        if ((command == "change_upper_level_of_susp_detection") ){
            short temp = 0;
            std::cin >> temp;
            if ((temp < 100) and (temp>5) or dev_mode ){
                upper_level_of_susp_detection = temp; 
            }
            else{
                std::cout<<invalid_value_error;
            }
            temp = 0;
        }
        if (command == "turn_on_devmod"){
            dev_mode = true;
            std::cout << "dev mod is enabled\n";
        }
        if (command == "turn_off_devmod"){
            dev_mode = false;
            std::cout << "dev mod is disabled\n";
        }
        if (command == "cahge_edege_of_suspicion_payload_weight"){
            short temp = 0;
            std::cin >> temp;
            if ((temp < 10000) and (temp>0) or dev_mode ){
                edege_of_suspicion_payload_weight = temp; 
            }else{
                std::cout<<invalid_value_error;
            }
            temp = 0;
        }
        if (command == "chint"){
            int temp = 0;
            std::cin >> temp;
            if ((temp < 100000) and (temp>0) or dev_mode ){
                freqwency_of_analysing = temp; 
            }else{
                std::cout<<invalid_value_error;
            }
            temp = 0; 
        }
        if (command == "expsettings"){
            make_impression_of_settings();
        }
        if (command == "impsettings"){
            reed_settings();
        }
        if (command == "settings"){
            std::cout <<"\npotr: "<<port<<std::endl;
            std::cout <<"lower level of suspicion detection: "<< lower_level_of_susp_detection<<std::endl;
            std::cout <<"upper level of suspicion detection: "<< upper_level_of_susp_detection<<std::endl;
            std::cout <<"devmode : "<<dev_mode<<std::endl;
            std::cout <<"edege of suspicion payload weight: "<< edege_of_suspicion_payload_weight<<std::endl;
            std::cout <<"interval of analysis: "<< freqwency_of_analysing<< "(milliseconds)"<<std::endl;
            
        }
        

    }
    
    
    
    return 0;
}
