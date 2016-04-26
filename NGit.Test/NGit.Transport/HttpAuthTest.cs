/*
 * Copyright (C) 2013, Microsoft Corporation
 *
 * This program and the accompanying materials are made available
 * under the terms of the Eclipse Distribution License v1.0 which
 * accompanies this distribution, is reproduced below, and is
 * available at http://www.eclipse.org/org/documents/edl-v10.php
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 * - Neither the name of the Eclipse Foundation, Inc. nor the
 *   names of its contributors may be used to endorse or promote
 *   products derived from this software without specific prior
 *   written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
using System;
using System.Net;
using NGit.Util;
using NUnit.Framework;
using Sharpen;

namespace NGit.Transport
{
	[TestFixture]
	public class HttpAuthTest
	{
		private const string digestHeader = "WWW-Authenticate: Digest qop=\"auth\",algorithm=MD5-sess,nonce=\"+Upgraded+v1b9...ba\",charset=utf-8,realm=\"Digest\"";

		private const string basicHeader = "WWW-Authenticate: Basic realm=\"everyones.loves.git\"";

		private const string ntlmHeader = "WWW-Authenticate: NTLM";

		private const string bearerHeader = "WWW-Authenticate: Bearer";

		private const string URL_SAMPLE = "http://everyones.loves.git/u/2";

		private const string BASIC = "Basic";

		private const string DIGEST = "Digest";

		[Test]
		public void TestHttpAuthScanResponse()
		{
			CheckResponse(new string[] { basicHeader }, BASIC);
			CheckResponse(new string[] { digestHeader }, DIGEST);
			CheckResponse(new string[] { basicHeader, digestHeader }, DIGEST);
			CheckResponse(new string[] { digestHeader, basicHeader }, DIGEST);
			CheckResponse(new string[] { ntlmHeader, basicHeader, digestHeader,
					bearerHeader }, DIGEST);
			CheckResponse(new string[] { ntlmHeader, basicHeader, bearerHeader },
					BASIC);
		}

		private static void CheckResponse(string[] headers, string expectedAuthMethod)
		{
			AuthHeadersResponse response = new AuthHeadersResponse(headers);
			HttpAuthMethod authMethod = HttpAuthMethod.ScanResponse(response);

			Assert.AreEqual(expectedAuthMethod, GetAuthMethodName(authMethod),
				"Wrong authentication method: expected " + expectedAuthMethod
						+ ", but received " + GetAuthMethodName(authMethod));
		}

		private static string GetAuthMethodName(HttpAuthMethod authMethod)
		{
			return authMethod.GetType().Name;
		}

		private class AuthHeadersResponse : HttpURLConnection
		{
			private WebHeaderCollection headerFields = new WebHeaderCollection();

			public AuthHeadersResponse(string[] authHeaders)
				: base(new Uri(URL_SAMPLE), HttpSupport.ProxyFor(ProxySelector.GetDefault(), new Uri(URL_SAMPLE)))
			{
				ParseHeaders(authHeaders);
			}

			public override string GetHeaderField(string name)
			{
				var values = headerFields.GetValues(name);

				return values != null && values.Length > 0 ? values.Last() : null;
			}

			public override WebHeaderCollection GetHeaders()
			{
				return headerFields;
			}

			private void ParseHeaders(string[] headers) {
				foreach (string header in headers)
				{
					int i = header.IndexOf(':');

					if (i < 0)
						continue;

					string key = header.Substring(0, i);
					string value = header.Substring(i + 1).Trim();

					headerFields.Add(key, value);
				}
			}
		}
	}
}
