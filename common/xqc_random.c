
#include "xqc_random.h"
#include "xqc_str.h"
#include "../include/xquic.h"


xqc_int_t
xqc_get_random(xqc_engine_t *engine, u_char *buf, size_t need_len)
{
    size_t total_read;
    ssize_t bytes_read;

    if ((size_t)engine->rand_buf_offset >= engine->rand_buf.len
        || engine->rand_buf.len - (size_t)engine->rand_buf_offset <= need_len) {

        /* not enough in rand_buf */

        if (engine->rand_fd == -1){

            engine->rand_fd = open("/dev/urandom", O_RDONLY|O_NONBLOCK);
            if(engine->rand_fd == -1){
                xqc_log(engine->log, XQC_LOG_WARN,
                                     "|random|can not open /dev/urandom|");
                return XQC_ERROR;
            }
        }

        total_read = 0;

        while (total_read < engine->rand_buf_size) {
	
            bytes_read = read(engine->rand_fd, 
				           engine->rand_buf.data + total_read, 
				           engine->rand_buf_size - total_read);
			
            if(bytes_read == -1){
				
                if(xqc_errno == EINTR){
                    continue;
                }
                if(xqc_errno == EAGAIN){
                    break;
                }
            }
			
            if (bytes_read <= 0){

                xqc_log(engine->log, XQC_LOG_WARN,
                                       "|random|fail to read bytes from /dev/urandom|");
				
                close(engine->rand_fd);
                engine->rand_fd = -1;
                break;
            }
			
            total_read += bytes_read;
        }
	 
        if(total_read < need_len){
            xqc_log(engine->log, XQC_LOG_WARN,
                                    "|random|can not generate rand buf|");
	        return XQC_ERROR;			
        }
		
	    engine->rand_buf_offset = 0;
	    engine->rand_buf.len = total_read;   
    }

    xqc_memcpy(buf, engine->rand_buf.data + engine->rand_buf_offset, need_len);

    engine->rand_buf_offset += need_len;

    return XQC_OK;
}


