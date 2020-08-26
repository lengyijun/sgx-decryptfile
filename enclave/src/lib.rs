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

#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_trts;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::*;
use sgx_types::metadata::*;
use sgx_trts::enclave;
//use sgx_trts::{is_x86_feature_detected, is_cpu_feature_supported};
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use std::backtrace::{self, PrintFormat};

#[no_mangle]
pub extern "C" fn sgx_decrypt(encrypted_filename_ptr: *const u8, encrypted_filename_len: usize, 
                                decrypted_filename_ptr:*const u8,decrypted_filename_len:usize) -> sgx_status_t {

    let encrypted_filename={
      let in_slice = unsafe { slice::from_raw_parts(encrypted_filename_ptr, encrypted_filename_len) };
      std::str::from_utf8(in_slice).unwrap()
    };

    let decrypted_filename={
      let out_slice = unsafe { slice::from_raw_parts(decrypted_filename_ptr, decrypted_filename_len) };
      std::str::from_utf8(out_slice).unwrap()
    };

    let content:Vec<u8>=std::sgxfs::read(encrypted_filename).unwrap();
    std::fs::write(decrypted_filename,content).unwrap();

    sgx_status_t::SGX_SUCCESS
}

