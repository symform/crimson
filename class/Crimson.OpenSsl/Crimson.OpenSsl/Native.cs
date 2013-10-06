//
// Author: 
//	Bassam Tabbara  <bassam@symform.com>
// 
// Copyright 2013 Symform Inc.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// #define OPENSSL_THREADING
// #define OPENSSL_FIPS

namespace Crimson.OpenSsl
{
	using Microsoft.Win32.SafeHandles;
	using System;
	using System.Threading;
	using System.Runtime.InteropServices;
	using System.Security.Cryptography;
	using System.Collections.Generic;

	/// <summary>
	/// Documentation can be found here: http://www.openssl.org/docs/crypto/EVP_DigestInit.html
	/// </summary>
	internal static class Native
	{
		private const string DllName = "libcrypto";

#if OPENSSL_THREADING
		private static object initLock = new object ();
		private static List<object> locks;
		private static Native.CRYPTO_locking_callback lockingDelegate;
		private static Native.CRYPTO_id_callback threadDelegate;
		private static HashSet<uint> threads;

		static Native ()
		{
			lock (initLock) {
				if (!IsInitialized ()) {
#if OPENSSL_FIPS
					try {
						FIPS_mode_set (1);
						Console.WriteLine ("FIPS mode set to 1");
					}
					catch (EntryPointNotFoundException) {
						Console.WriteLine ("FIPS not found.");
					}
#endif
					InitializeThreads ();
					AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
				}
			}
		}

		private static void OnProcessExit (object sender, EventArgs args)
		{
			lock (initLock) {
				if (IsInitialized ()) {
					AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
					UninitializeThreads ();
				}
			}
		}
#endif

		public static void ExpectSuccess (bool ret)
		{
			if (!ret) {
				throw new CryptographicException ();
			}
		}

		#region versioninfo
		[Serializable]
		public enum SSLeayVersionType
		{
			SSLEAY_VERSION = 0,
			SSLEAY_CFLAGS = 2,
			SSLEAY_BUILT_ON = 3,
			SSLEAY_PLATFORM = 4,
			SSLEAY_DIR = 5,
		}

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false, CharSet = CharSet.Ansi)]
		public extern static IntPtr SSLeay_version (SSLeayVersionType type);
		#endregion

#if OPENSSL_FIPS
		[DllImport(DllName, CallingConvention=CallingConvention.Cdecl)]
		public extern static int FIPS_mode_set(int onoff);
#endif

#if OPENSSL_THREADING
		#region threading
		public const int CRYPTO_LOCK = 1;

		[UnmanagedFunctionPointer (CallingConvention.Cdecl)]
		public delegate void CRYPTO_locking_callback (int mode, int type, string file, int line);

		[UnmanagedFunctionPointer (CallingConvention.Cdecl)]
		public delegate uint CRYPTO_id_callback ();

		[DllImport(DllName, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_set_id_callback (CRYPTO_id_callback cb);

		[DllImport(DllName, CallingConvention=CallingConvention.Cdecl)]
		public extern static IntPtr CRYPTO_get_id_callback ();

		[DllImport(DllName, CallingConvention=CallingConvention.Cdecl)]
		public extern static void CRYPTO_set_locking_callback (CRYPTO_locking_callback cb);

		[DllImport(DllName, CallingConvention=CallingConvention.Cdecl)]
		public extern static int CRYPTO_num_locks ();

		[DllImport(DllName, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ERR_remove_state (uint pid);

		[DllImport(DllName, CallingConvention=CallingConvention.Cdecl)]
		public extern static void ERR_clear_error ();

		private static bool IsInitialized ()
		{
			return Native.CRYPTO_get_id_callback () != IntPtr.Zero;
		}

		private static void InitializeThreads ()
		{
			int lockCount = Native.CRYPTO_num_locks ();

			locks = new List<object> (lockCount);
			for (int i = 0; i < lockCount; i++) {
				locks.Add (new object ());
			}

			threads = new HashSet<uint> ();

			lockingDelegate = LockingCallback;
			Native.CRYPTO_set_locking_callback (lockingDelegate);

			threadDelegate = ThreadCallback;
			Native.CRYPTO_set_id_callback (threadDelegate);
		}

		private static void UninitializeThreads ()
		{
			// Cleanup the thread lock objects
			Native.CRYPTO_set_locking_callback (null);
			lockingDelegate = null;

			Native.CRYPTO_set_id_callback (null);
			threadDelegate = null;

			if (threads != null) {
				foreach (uint id in threads) {
					Native.ERR_clear_error ();
					Native.ERR_remove_state (id);
				}
				threads.Clear ();
			}
		}

		public static void LockingCallback (int mode, int type, string file, int line)
		{
			if ((mode & Native.CRYPTO_LOCK) == Native.CRYPTO_LOCK) {
				Monitor.Enter (locks [type]);
			} else {
				Monitor.Exit (locks [type]);
			}
		}

		public static uint ThreadCallback ()
		{
			uint thread = (uint)Thread.CurrentThread.ManagedThreadId;

			lock (threads) {
				threads.Add (thread);
			}

			return thread;
		}
		#endregion
#endif

		#region digest
		public const int MaximumDigestSize = 64;

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeDigestHandle EVP_md5 ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeDigestHandle EVP_sha1 ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeDigestHandle EVP_sha256 ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static IntPtr EVP_MD_CTX_create ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static IntPtr EVP_MD_CTX_init (IntPtr ctx);

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static void EVP_MD_CTX_cleanup (IntPtr ctx);

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static void EVP_MD_CTX_destroy (IntPtr ctx);

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public extern static bool EVP_DigestInit_ex (IntPtr ctx, SafeDigestHandle type, IntPtr impl);

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public extern static bool EVP_DigestUpdate (IntPtr ctx, IntPtr d, uint cnt);

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public extern static bool EVP_DigestFinal_ex (IntPtr ctx, IntPtr md, out uint s);

		internal sealed class SafeDigestHandle : SafeHandleZeroOrMinusOneIsInvalid
		{
			private SafeDigestHandle () :
                base (false)
			{
			}

			protected override bool ReleaseHandle ()
			{
				return false;
			}
		}

		internal sealed class SafeDigestContextHandle : SafeHandleZeroOrMinusOneIsInvalid
		{
			internal SafeDigestContextHandle (IntPtr handle, bool ownsHandle) :
                base(ownsHandle)
			{
				this.SetHandle (handle);
			}

			private SafeDigestContextHandle () :
                base (true)
			{
			}

			protected override bool ReleaseHandle ()
			{
				EVP_MD_CTX_destroy (this.handle);
				return true;
			}
		}
		#endregion

		#region ciphers
		[Serializable]
		public enum CipherOperation
		{
			Unchanged = -1,
			Decrypt = 0,
			Encrypt = 1,
		}

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeCipherHandle EVP_aes_128_cbc ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeCipherHandle EVP_aes_192_cbc ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeCipherHandle EVP_aes_256_cbc ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeCipherHandle EVP_aes_128_ecb ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeCipherHandle EVP_aes_192_ecb ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeCipherHandle EVP_aes_256_ecb ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		public extern static SafeCipherContextHandle EVP_CIPHER_CTX_new ();

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		private extern static void EVP_CIPHER_CTX_free (IntPtr a);

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public extern static bool EVP_CIPHER_CTX_set_key_length (SafeCipherContextHandle x, int keylen);

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public extern static bool EVP_CIPHER_CTX_set_padding (SafeCipherContextHandle x, int padding);

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public extern static bool EVP_CipherInit_ex (SafeCipherContextHandle ctx, SafeCipherHandle type, IntPtr impl, IntPtr key, IntPtr iv, CipherOperation enc);

		[DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
		[return: MarshalAs (UnmanagedType.Bool)]
		public extern static bool EVP_CipherUpdate (SafeCipherContextHandle ctx, IntPtr outb, out int outl, IntPtr inb, int inl);

		internal sealed class SafeCipherHandle : SafeHandleZeroOrMinusOneIsInvalid
		{
			private SafeCipherHandle () :
                base (false)
			{
			}

			protected override bool ReleaseHandle ()
			{
				return false;
			}
		}

		internal sealed class SafeCipherContextHandle : SafeHandleZeroOrMinusOneIsInvalid
		{
			internal SafeCipherContextHandle (IntPtr handle, bool ownsHandle) :
                base (ownsHandle)
			{
				this.SetHandle (handle);
			}

			private SafeCipherContextHandle () :
                base (true)
			{
			}

			protected override bool ReleaseHandle ()
			{
				EVP_CIPHER_CTX_free (this.handle);
				return true;
			}
		}
		#endregion
	}
}
