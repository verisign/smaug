/*
Copyright (c) <2014> Verisign, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights 
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
copies of the Software, and to permit persons to whom the Software is furnished 
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
// #include <stdlib.h>
// #include <string.h>
#include <inttypes.h>

#include "dane_cert.h"

extern "C" {
#include <getdns/getdns.h>
}

Certificate::Certificate() {
	record = "";
	certType = UNKNOWN_CERTIFICATE_TYPE;
	certLen  = 0;
	memset( &cert[0], '\0', MAX_CERTIFICATE_LEN );
	// valid = false;
};

Certificate::~Certificate() {
	return;
}

void Certificate::setCertificateInfo(const std::string record) {
	this->record = record;
	if (getDnsData()==1) {
		valid = true;
	    //add labels to the certs

	} else {
		valid = false;
	}
}

uint16_t Certificate::getCertType() {
	return certType;
}

uint32_t Certificate::getResponseStatus() {
	return getdns_response_status;
}

void Certificate::printCert() {
	std::cout << "Certificate::printCert key length [" << std::dec
		<< certLen
		<< "]" << std::endl;
uint8_t *ptr = &cert[0];
std::cout << "Certificate::printCert key value [" << std::endl;
	for (uint32_t loop=0; loop<certLen; ++loop) {
		std::cout << std::hex << uint8_t(*ptr);
		++ptr;
	}
	std::cout << "]"
<< std::endl;	
return;
}

uint32_t  Certificate::getCert(uint8_t * certBuf, uint32_t certSize, 
                               uint8_t& usage, uint8_t& type, uint8_t& selector) {
	if (!certLen){
		return 0;
	}
	if (certLen > certSize) {
	    // destination buffer too short
		std::cerr << "Destination buffer for certificate is too small"
		<< std::endl;
		exit(-1);
	}
	memcpy(certBuf, (cert+3), certLen-3);
        usage     = cert[0];	
        type      = cert[1];	
        selector  = cert[2];	
	printf("Usage type selector = %u %u %u\n", usage, type, selector);
	return certLen-3;
}


int Certificate::getDnsData( ) {
    getdns_return_t context_create_return;
    
    uint32_t this_error = 0;
    
    struct getdns_context *this_context = NULL;
    struct getdns_dict    *this_response = NULL;
    
    // const char *this_name         = &domainAddr[0];
    const char *this_name         = record.c_str();
    uint16_t    this_request_type = DANE_EMAIL_RR_TYPE;

    getdns_return_t this_ret;

    /* Create the DNS context for this call */
    context_create_return = getdns_context_create(&this_context, 1);
    if (context_create_return != GETDNS_RETURN_GOOD) {
	std::cerr << "Trying to create the context failed: ["
		  << context_create_return << "]" << std::endl;
	return (GETDNS_RETURN_GENERIC_ERROR);
    }
    
    // getdns_dict * this_extensions = NULL;
	getdns_dict * this_extensions = getdns_dict_create();
	// reference: https://github.com/getdnsapi/getdns-python-bindings/blob/master/doc/functions.rst
    this_ret = getdns_dict_set_int(this_extensions, "add_warning_for_bad_dns", GETDNS_EXTENSION_TRUE);
    this_ret = getdns_dict_set_int(this_extensions, "dnssec_return_status", GETDNS_EXTENSION_TRUE);
    this_ret = getdns_dict_set_int(this_extensions, "dnssec_return_only_secure", GETDNS_EXTENSION_TRUE);

    if (this_ret != GETDNS_RETURN_GOOD) {
            std::cerr << "Trying to set an extension failed: " << this_ret << std::endl;
            getdns_dict_destroy(this_extensions);
            getdns_context_destroy(this_context);
                return(GETDNS_RETURN_GENERIC_ERROR);
     }

    /* Make the call */
    getdns_return_t dns_request_return =
	getdns_general_sync(this_context, this_name, this_request_type,
			    		this_extensions, &this_response);
    
    if (dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME) {
	std::cerr << "A bad domain name was used: [" 
		  << this_name << "]. Exiting." << std::endl;
	return (GETDNS_RETURN_GENERIC_ERROR);
    } else {
	/* Be sure the search returned something */
	this_ret = getdns_dict_get_int(this_response, (char *)"status", &this_error);	// Ignore any error
	if (this_error != GETDNS_RESPSTATUS_GOOD) {	// If the search didn't return "good"
	    
	    std::cerr << "The search had no results, and a return value of [" << this_error 
		      <<  "]." << std::endl;
	    return (GETDNS_RETURN_GENERIC_ERROR);
	}

#if DEBUG_LEVEL_HIGH==1
	std::cout << "response [" << getdns_pretty_print_dict(this_response) << "]" << std::endl;
#endif

	// if (this_extensions) {
	// 	// getdns_response_status = this_extensions;
	// 	this_ret = getdns_dict_get_int(this_response, (char *)"dnssec_status", &this_error);
	// 	if (this_ret == GETDNS_DNSSEC_INSECURE)

	// }
	/* Find all the answers returned */
	struct getdns_list *these_answers;
	this_ret =
	    getdns_dict_get_list(this_response, (char *)"replies_tree",
				 &these_answers);
	if (this_ret == GETDNS_RETURN_NO_SUCH_DICT_NAME) {
	    std::cerr << "Weird: the response had no error, but also no replies_tree. Exiting."
		      << std::endl;
	    return 0;
	}

	size_t num_answers;
	this_ret = getdns_list_get_length(these_answers, &num_answers);

	/* Go through each answer */
	for (size_t rec_count = 0; rec_count < num_answers;
	     ++rec_count) {
	    struct getdns_dict *this_record;
	    this_ret = getdns_list_get_dict(these_answers, rec_count, &this_record);	// Ignore any error
	    /* Get the answer section */
	    struct getdns_list *this_answer;
	    this_ret = getdns_dict_get_list(this_record, (char *)"answer", &this_answer);	// Ignore any error
	    /* Get each RR in the answer section */
	    size_t num_rrs_ptr;
	    this_ret =
		getdns_list_get_length(this_answer, &num_rrs_ptr);

	    for (size_t rr_count = 0; rr_count < num_rrs_ptr;
		 ++rr_count) {
		struct getdns_dict *this_rr = NULL;
		this_ret = getdns_list_get_dict(this_answer, rr_count, &this_rr);	// Ignore any error

		/* Get the RDATA */
		struct getdns_dict *this_rdata = NULL;
		this_ret = getdns_dict_get_dict(this_rr, (char *)"rdata", &this_rdata);	// Ignore any error

		/* Get the RDATA type */
		uint32_t this_type;
		this_ret = getdns_dict_get_int(this_rr, (char *)"type", &this_type);	// Ignore any error

#if DEBUG_LEVEL_HIGH==1		
		std::cout << "RR_Type [" << this_type << "]" << std::endl;
#endif
    
		// check for the smime type
		if (this_type == DANE_EMAIL_RR_TYPE) {
		    struct getdns_bindata *rdata =
			NULL;
		    this_ret =
			getdns_dict_get_bindata(this_rdata,
						(char *)"rdata_raw", &rdata);
		    if (this_ret != GETDNS_RETURN_GOOD) {
			if (this_ret ==
			    GETDNS_RETURN_NO_SUCH_DICT_NAME) {
			    std::cerr <<
				"Weird: the A record at [" << rr_count  << "] in record at [" 
							   << rec_count << "] had no address. Exiting." 
							   << std::endl;
			    return 0;
			} else {
			    std::cerr << "ERROR on fetch of bindata" 
				      << std::endl;
			}
		    } else {
#if DEBUG_LEVEL_MEDIUM==1			
			std::cout << "Found public key" << std::endl;
#endif
			certLen = rdata->size;
			memcpy(&cert, rdata->data, certLen);
			break;
		    }
		}

    
	    }
	}
    }
    /* Clean up */
    getdns_dict_destroy(this_extensions);
    getdns_context_destroy(this_context);
    
    return 0;
}
