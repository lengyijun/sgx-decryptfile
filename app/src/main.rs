// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

extern crate sgx_types;
extern crate sgx_urts;
extern crate path_absolutize;
#[macro_use]
extern crate lazy_static;

use std::path::Path;
use path_absolutize::*;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::path::PathBuf;

lazy_static! {
    static ref ENCLAVE_FILE: String= {
          let mut p=std::env::current_exe().unwrap();
          p.pop();
          p.push( "enclave.signed.so" );
          String::from(p.to_str().unwrap() )
        };
}

extern {
     fn sgx_decrypt(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                    encrypted_filename_ptr: *const u8, encrypted_filename_len: usize, 
                    decrypted_filename_ptr:*const u8,decrypted_filename_len:usize) -> sgx_status_t ;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(&*ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

/// sgx-decrypt <encrypt_file> -o <decrypt_file>
fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };


    let input= std::env::args().nth(1).expect("three parameter needed");
    let y=Path::new(&input).absolutize().unwrap();
    let encrypted_filepath = y.to_str().unwrap();

    let output= std::env::args().nth(3).expect("three parameter needed");
    let x=Path::new(&output).absolutize().unwrap();
    let decrypted_filepath = x.to_str().unwrap();

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        sgx_decrypt(enclave.geteid(),
                      &mut retval,
                      encrypted_filepath.as_ptr() as * const u8,
                      encrypted_filepath.len(),
                      decrypted_filepath.as_ptr() as * const u8,
                      decrypted_filepath.len()
                      )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    println!("[+] sgx_decrypt success...");
    enclave.destroy();
}
