@load base/protocols/ssh

redef record SSH::Info += {
    ## tells the authentication method of the SSH authentication attempt
    authentication_method: string &default="" &log;
};

global prevprev_packet_size: count = 0;
global prevprev_packet_direction: bool = T;

global prev_packet_size: count = 0;
global prev_packet_direction: bool = T;

global actual_packet_size: count = 0;
global actual_packet_direction: bool = F;

global auth_service_request_size = -1;
global auth_service_request_response_size = 0;


event ssh_auth_attempted(c: connection, authenticated: bool)
{   
    local method: string = "?";
    if (c$ssh$authentication_method != ""){
        c$ssh$authentication_method = c$ssh$authentication_method + ",";
    }
    local delta_prev = prev_packet_size - auth_service_request_response_size;
    local delta_prevprev = prevprev_packet_size - auth_service_request_size;
    print delta_prev;
    if (delta_prev == 96){
        method = "password";
    }
    if (delta_prev == 32){
        method = "challenge-response";
    }
    if (delta_prev >= 256 && delta_prev <= 640){
        if (delta_prevprev == 16){
            method = "hostbased";
        }
        if (delta_prevprev >= 112 && delta_prevprev <= 432){
            method = "publickey";
        }
    }

    c$ssh$authentication_method = c$ssh$authentication_method + method;
}

event ssh_encrypted_packet(c: connection, orig: bool, len: count)
{
    if (auth_service_request_size == 0 && !orig)
        auth_service_request_size = len;
    if (auth_service_request_response_size == 0 && orig)
        auth_service_request_response_size = len;

    prevprev_packet_size = prev_packet_size;
    prevprev_packet_direction = prev_packet_direction;

    prev_packet_size = actual_packet_size;
    prev_packet_direction = actual_packet_direction;
    
    actual_packet_size = len;
    actual_packet_direction = orig;

    if (auth_service_request_size < 0)
        auth_service_request_size = auth_service_request_size + 1;
    if (auth_service_request_response_size < 0)
        auth_service_request_response_size = auth_service_request_response_size + 1;
}
