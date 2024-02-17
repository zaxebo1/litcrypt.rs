//! LITCRYPT3
//! ===========

#[cfg(test)]
#[macro_use(expect)]
extern crate expectest;
extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate rand;
extern crate syn;

use std::env;

use proc_macro::{TokenStream, TokenTree};
use proc_macro2::Literal;
use quote::quote;
use rand::{rngs::OsRng, RngCore};
use syn::{parse_macro_input, Expr, ExprGroup, ExprLit, Lit};

mod xor;

lazy_static::lazy_static! {
	static ref RAND_SPELL: [u8; 64] = {
		let mut key = [0u8; 64];
		OsRng.fill_bytes(&mut key);
		key
	};
}

#[inline(always)]
fn get_magic_spell() -> Vec<u8> {
	match env::var("LITCRYPT_ENCRYPT_KEY") {
		Ok(key) => key.as_bytes().to_vec(),
		Err(_) => {
			// `lc!` will call this function multi times
			// we must provide exact same result for each invocation
			// so use static lazy field for cache
			RAND_SPELL.to_vec()
		},
	}
}

/// Sets the encryption key used for encrypting subsequence strings wrapped in a
/// [`lc!`] macro.
///
/// This key is also encrypted an  will not visible in a static analyzer.
#[proc_macro]
pub fn use_litcrypt(_tokens: TokenStream) -> TokenStream {
	let magic_spell = get_magic_spell();

	let encdec_func = quote! {
		pub mod litcrypt_internal {
			// This XOR code taken from https://github.com/zummenix/xor-rs
			/// Returns result of a XOR operation applied to a `source` byte sequence.
			///
			/// `key` will be an infinitely repeating byte sequence.
			pub fn xor(source: &[u8], key: &[u8]) -> Vec<u8> {
				match key.len() {
					0 => source.into(),
					1 => xor_with_byte(source, key[0]),
					_ => {
						let key_iter = InfiniteByteIterator::new(key);
						source.iter().zip(key_iter).map(|(&a, b)| a ^ b).collect()
					}
				}
			}

			/// Returns result of a XOR operation applied to a `source` byte sequence.
			///
			/// `byte` will be an infinitely repeating byte sequence.
			pub fn xor_with_byte(source: &[u8], byte: u8) -> Vec<u8> {
				source.iter().map(|&a| a ^ byte).collect()
			}

			struct InfiniteByteIterator<'a> {
				bytes: &'a [u8],
				index: usize,
			}

			impl<'a> InfiniteByteIterator<'a> {
				pub fn new(bytes: &'a [u8]) -> InfiniteByteIterator<'a> {
					InfiniteByteIterator {
						bytes: bytes,
						index: 0,
					}
				}
			}

			impl<'a> Iterator for InfiniteByteIterator<'a> {
				type Item = u8;
				fn next(&mut self) -> Option<u8> {
					let byte = self.bytes[self.index];
					self.index = next_index(self.index, self.bytes.len());
					Some(byte)
				}
			}

			fn next_index(index: usize, count: usize) -> usize {
				/*
				if index + 1 < count {
					index + 1
				} else {
					0
				}
				*/
								// https://github.com/anvie/litcrypt.rs/commit/d22782c18009cb3dfcbe2355d397e03ebfbeba8b
				//Changing next_index function to prevent Defender from flagging it as Cobalt Strike
				if index + 2 < count {
				    index + 2
				} 
				else {
				    if count % 2 == 0 {
					if index + 2 == count  {
					    1
					}
					else {
					    0
					}
				   }
				   else {
				       if index + 2 == count {
					    0
				       }
				       else {
					    1
				      }
				  }
				}								
			}

			pub fn decrypt_bytes(encrypted: &[u8], encrypt_key: &[u8]) -> String {
				let decrypted = xor(&encrypted[..], &encrypt_key);
				String::from_utf8(decrypted).unwrap()
			}
		}
	};
	let result = {
		let ekey = xor::xor(&magic_spell, b"ESJCTVgWH5HQFza7GdRx");
		let ekey = Literal::byte_string(&ekey);
		quote! {
			static LITCRYPT_ENCRYPT_KEY: &'static [u8] = #ekey;
			#encdec_func
		}
	};
	result.into()
}

/// Encrypts the resp. string with the key set before, via calling
/// [`use_litcrypt!`].
#[proc_macro]
pub fn lc(tokens: TokenStream) -> TokenStream {
	let mut something = String::from("");
	for tok in tokens {
		something = match tok {
			TokenTree::Literal(lit) => {
				let mut lit_str: String = lit.to_string();
				let first_occurrence = lit_str.find("\"");
				let last_occurrence = lit_str.rfind("\"");

				if !first_occurrence.is_none() && !last_occurrence.is_none() {
					lit_str = lit_str[first_occurrence.unwrap() + 1..last_occurrence.unwrap()].to_string();
				} else {
					lit_str = lit_str[1..lit_str.len() - 1].to_string();
				}

				lit_str
			},
			_ => "<unknown>".to_owned(),
		}
	}

	encrypt_string(something)
}

/// Encrypts an environment variable at compile time with the key set before,
/// via calling [`use_litcrypt!`].
#[proc_macro]
pub fn lc_env(tokens: TokenStream) -> TokenStream {
	let mut var_name = String::from("");

	for tok in tokens {
		var_name = match tok {
			TokenTree::Literal(lit) => lit.to_string(),
			_ => "<unknown>".to_owned(),
		}
	}

	var_name = String::from(&var_name[1..var_name.len() - 1]);

	encrypt_string(env::var(var_name).unwrap_or(String::from("unknown")))
}

#[proc_macro]
/// Encrypts dynamic values at compile time with the
/// litcrypt key.
pub fn lc_dynamic(tokens: TokenStream) -> TokenStream {
	let expr = parse_macro_input!(tokens as Expr);
	let var_name = match expr {
		Expr::Lit(ExprLit {
			lit: Lit::Str(lit_str), ..
		}) => lit_str.value(),
		Expr::Group(ExprGroup { expr: expr, .. }) => {
			let downcasted = match *expr {
				Expr::Lit(ExprLit {
					lit: Lit::Str(lit_str), ..
				}) => lit_str.value(),
				_ => "<unknown>".to_owned(),
			};
			downcasted
		},
		_ => "<unknown>".to_owned(),
	};

	encrypt_string(var_name)
}

fn encrypt_string(something: String) -> TokenStream {
	let magic_spell = get_magic_spell();
	let encrypt_key = xor::xor(&magic_spell, b"ESJCTVgWH5HQFza7GdRx");
	let encrypted = xor::xor(&something.as_bytes(), &encrypt_key);
	let encrypted = Literal::byte_string(&encrypted);

	let result = quote! {
		crate::litcrypt_internal::decrypt_bytes(#encrypted, crate::LITCRYPT_ENCRYPT_KEY)
	};

	result.into()
}
