//The MIT License ( MIT )
//
//Copyright ( c ) 2015 Yuriy
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files ( the "Software" ), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions :
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.


#include "stdafx.h"
#pragma comment(lib, "crypt32.lib")
#include "Signer.hpp"

using std::ifstream;
using std::ofstream;
using std::wcout;
using std::endl;
using std::set;
using std::map;

DWORD Certificate::DISPLAY_TYPE = 4;
std::string wide2asci ( wstring wstr ) {
	size_t size = wstr.size ();
	char *buffer = new char[ size ];
	wcstombs ( buffer, wstr.c_str (), size );
	buffer[ wstr.size () ] = '\0';
	std::string res ( buffer );
	return res;
}

void readfile ( ifstream &stream, DataBlob& blob ) {
	stream.seekg ( 0, std::ios::end );
	blob.cbData = stream.tellg ();
	stream.seekg ( 0, std::ios::beg );
	blob.pbData = new BYTE[ 3 * blob.cbData ];
	stream.read ( (char*)blob.pbData, blob.cbData );
}

int _tmain ( int argc, _TCHAR* argv[] ) {
	DataBlob Decoded, Signed;
	try {
		map<wstring, wstring> params;
		set<wstring> flags;

		for ( int i = 1; i < argc; i++ ) {
			wchar_t *arg = wcstok ( argv[ i ], L"=\0" ), *par;
			if ( par = wcstok ( NULL, L"=\0" ) ) {
				params[ arg ] = par;
			} else {
				flags.insert ( arg );
			}
		}

		int debug = 2;
		if ( debug ) {
			params[ L"store" ] = L"My";
			params[ L"subj" ] = L"yuriy";
			if ( debug == 2 ) {
				flags.insert ( L"verify" );
				params[ L"data" ] = L"test.bin";
				params[ L"sign" ] = L"test.sgn";
			} else if ( debug == 1 ) {
				flags.insert ( L"sign" );
				params[ L"input" ] = L"test.bin";
				params[ L"output" ] = L"test.sgn";
			}
		}

		auto store = Store::Open ( params[ L"store" ] );

		/*for ( auto *cert : *store ) {
			wcout << cert->Name () << endl;
			for ( auto &prop : *cert ) {
			wcout << BlobPrinter ( prop.first, prop.second );
			} wcout << endl;
			}*/

		auto cert = store->Find ( params[ L"subj" ] );

		if ( flags.find ( L"sign" ) != flags.end () ) {
			DataBlob blob;
			ifstream input = ifstream ( wide2asci ( params[ L"input" ] ), std::ios::binary );
			ofstream output = ofstream ( wide2asci ( params[ L"output" ] ), std::ios::binary );
			readfile ( input, blob );
			Signed = cert->Sign ( blob );
			output.write ( (const char*)Signed.pbData, Signed.cbData );
			return 0;
		} else if ( flags.find ( L"verify" ) != flags.end () ) {
			DataBlob blob1, blob2;
			ifstream data = ifstream ( wide2asci ( params[ L"data" ] ), ifstream::binary );
			ifstream sign = ifstream ( wide2asci ( params[ L"sign" ] ), ifstream::binary );
			readfile ( data, blob1 );
			readfile ( sign, blob2 );
			wcout << ( cert->Verify ( &blob2, &blob1 )
				? L"Verification success!"
				: L"Verification failed!" ) << endl;
			return 0;
		}
	} catch ( CertificateException e ) {
		wcout << e.what () << endl;
	}
	return 1;
}


BlobPrinter::BlobPrinter ( wstring name, DataBlob data ) {
	this->name = name;
	this->data = data;
}

std::wostream& operator<< ( std::wostream& os, const BlobPrinter& blob ) {
	os << blob.name << ": ";
	int len = 80 - blob.name.size () - 2;
	for ( int i = 0; i < blob.data.cbData; ++i ) {
		if ( i % ( len / 2 ) == 0 && i != 0 ) {
			os << endl;
			for ( int j = blob.name.size () + 2; j; j-- ) {
				os << " ";
			}
		}
		wchar_t buff[ 4 ];
		wsprintf ( buff, L"%02X", blob.data.pbData[ i ] );
		os << buff;
	}

	os << endl;
	return os;
}

Win32Exception::Win32Exception ( const wstring messageArg ) {
	DWORD errorMessageID = GetLastError ();
	if ( errorMessageID == 0 ) {
		this->message = messageArg;
	}

	LPWSTR messageBuffer = nullptr;
	size_t size = FormatMessageW ( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID ( LANG_NEUTRAL, SUBLANG_DEFAULT ), (LPWSTR)&messageBuffer, 0, NULL );
	wstring message ( messageBuffer, size - 3 );
	LocalFree ( messageBuffer );
	this->message = ( messageArg != L""
		? messageArg + L": "
		: L"" ) + message;
}

Certificate::Certificate ( PCCERT_CONTEXT context ) {
	this->context = context;
	wchar_t buff[ 256 ];
	if ( !CertGetNameString ( context, DISPLAY_TYPE, 0, NULL, buff, 128 ) ) {
		throw CertificateException ( L"CertGetName failed." );
	} name = buff;

	DWORD prop = 0;
	while ( prop = CertEnumCertificateContextProperties ( context, prop ) ) {
		wstring propName; DataBlob blob;
		switch ( prop ) {
		case CERT_FRIENDLY_NAME_PROP_ID: propName = L"Display name"; break;
		case CERT_SIGNATURE_HASH_PROP_ID: propName = L"Signature hash identifier"; break;
		case CERT_KEY_PROV_HANDLE_PROP_ID: propName = L"KEY PROVE HANDLE"; break;
		case CERT_KEY_PROV_INFO_PROP_ID: propName = L"KEY PROV INFO PROP ID"; break;
		case CERT_SHA1_HASH_PROP_ID: propName = L"SHA1 HASH identifier"; break;
		case CERT_MD5_HASH_PROP_ID: propName = L"md5 hash identifier"; break;
		case CERT_KEY_CONTEXT_PROP_ID: propName = L"KEY CONTEXT PROP identifier"; break;
		case CERT_KEY_SPEC_PROP_ID: propName = L"KEY SPEC PROP identifier"; break;
		case CERT_ENHKEY_USAGE_PROP_ID: propName = L"ENHKEY USAGE PROP identifier";  break;
		case CERT_NEXT_UPDATE_LOCATION_PROP_ID: propName = L"NEXT UPDATE LOCATION PROP identifier"; break;
		case CERT_PVK_FILE_PROP_ID: propName = L"PVK FILE PROP identifier"; break;
		case CERT_DESCRIPTION_PROP_ID: propName = L"DESCRIPTION PROP identifier";  break;
		case CERT_ACCESS_STATE_PROP_ID: propName = L"ACCESS STATE PROP identifier"; break;
		case CERT_SMART_CARD_DATA_PROP_ID: propName = L"SMART_CARD DATA PROP identifier"; break;
		case CERT_EFS_PROP_ID: propName = L"EFS PROP identifier"; break;
		case CERT_FORTEZZA_DATA_PROP_ID: propName = L"FORTEZZA DATA PROP identifier"; break;
		case CERT_ARCHIVED_PROP_ID: propName = L"ARCHIVED PROP identifier"; break;
		case CERT_KEY_IDENTIFIER_PROP_ID: propName = L"KEY IDENTIFIER PROP identifier"; break;
		case CERT_AUTO_ENROLL_PROP_ID: propName = L"AUTO ENROLL identifier"; break;
		}

		if ( !CertGetCertificateContextProperty ( context, prop, NULL, &( blob.cbData ) ) ) {
			throw CertificateException ( L"Call #1 to GetCertContextProperty failed." );
		}
		blob.pbData = new BYTE[ blob.cbData ];
		if ( !CertGetCertificateContextProperty ( context, prop, blob.pbData, &( blob.cbData ) ) ) {
			throw CertificateException ( L"Call #2 failed." );
		}

		properties[ propName ] = blob;
	}
}

DataBlob Certificate::Sign ( DataBlob blob, DWORD encoding, LPSTR algo ) {
	const BYTE* pbContent = blob.pbData;
	DWORD cbContent = blob.cbData;

	HCRYPTPROV hCryptProv;

	CMSG_SIGNER_ENCODE_INFO SignerEncodeInfo;
	CMSG_SIGNER_ENCODE_INFO SignerEncodeInfoArray[ 1 ];
	CERT_BLOB SignerCertBlob;
	CERT_BLOB SignerCertBlobArray[ 1 ];
	CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo;
	DWORD cbEncodedBlob;
	BYTE* pbEncodedBlob;
	HCRYPTMSG hMsg;
	DWORD dwKeySpec;

	CRYPT_VERIFY_MESSAGE_PARA msgPara;

	if ( !( CryptAcquireCertificatePrivateKey ( context, 0, NULL, &hCryptProv, &dwKeySpec, NULL ) ) ) {
		throw CertificateException ( L"CryptAcquireContext failed" );
	}

	memset ( &SignerEncodeInfo, 0, sizeof ( CMSG_SIGNER_ENCODE_INFO ) );
	SignerEncodeInfo.cbSize = sizeof ( CMSG_SIGNER_ENCODE_INFO );
	SignerEncodeInfo.pCertInfo = context->pCertInfo;
	SignerEncodeInfo.hCryptProv = hCryptProv;
	SignerEncodeInfo.dwKeySpec = dwKeySpec;
	SignerEncodeInfo.HashAlgorithm.pszObjId = szOID_RSA_MD5;
	SignerEncodeInfo.pvHashAuxInfo = NULL;


	SignerEncodeInfoArray[ 0 ] = SignerEncodeInfo;
	SignerCertBlob.cbData = context->cbCertEncoded;
	SignerCertBlob.pbData = context->pbCertEncoded;

	SignerCertBlobArray[ 0 ] = SignerCertBlob;
	memset ( &SignedMsgEncodeInfo, 0, sizeof ( CMSG_SIGNED_ENCODE_INFO ) );
	SignedMsgEncodeInfo.cbSize = sizeof ( CMSG_SIGNED_ENCODE_INFO );
	SignedMsgEncodeInfo.cSigners = 1;
	SignedMsgEncodeInfo.rgSigners = SignerEncodeInfoArray;
	SignedMsgEncodeInfo.cCertEncoded = 1;
	SignedMsgEncodeInfo.rgCertEncoded = SignerCertBlobArray;

	if ( !( cbEncodedBlob = CryptMsgCalculateEncodedLength ( encoding, 0, CMSG_SIGNED, &SignedMsgEncodeInfo, NULL, cbContent ) ) ) {
		throw CertificateException ( L"Getting cbEncodedBlob length failed." );
	}

	if ( !( pbEncodedBlob = (BYTE *)malloc ( cbEncodedBlob ) ) ) {
		throw CertificateException ( L"Malloc operation failed." );
	}

	if ( !( hMsg = CryptMsgOpenToEncode ( encoding, CMSG_DETACHED_FLAG, CMSG_SIGNED, &SignedMsgEncodeInfo, NULL, NULL ) ) ) {
		throw CertificateException ( L"OpenToEncode failed" );
	}

	if ( !( CryptMsgUpdate ( hMsg, pbContent, cbContent, TRUE ) ) ) {
		throw CertificateException ( L"MsgUpdate failed" );
	}

	if ( !CryptMsgGetParam ( hMsg, CMSG_CONTENT_PARAM, 0, pbEncodedBlob, &cbEncodedBlob ) ) {
		throw CertificateException ( L"MsgGetParam failed." );
	}

	CryptMsgClose ( hMsg );
	CryptReleaseContext ( hCryptProv, 0 );

	DataBlob res; res.cbData = cbEncodedBlob; res.pbData = pbEncodedBlob;
	return res;
}

bool Certificate::Verify ( DataBlob *sign, DataBlob *message, DWORD encoding ) {
	const BYTE* pbContent = message->pbData;
	DWORD cbContent = message->cbData;

	HCRYPTPROV hCryptProv;
	HCERTSTORE hStoreHandle;
	PCCERT_CONTEXT pSignerCert;

	CMSG_SIGNER_ENCODE_INFO SignerEncodeInfo;
	CMSG_SIGNER_ENCODE_INFO SignerEncodeInfoArray[ 1 ];
	CERT_BLOB SignerCertBlob;
	CERT_BLOB SignerCertBlobArray[ 1 ];
	CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo;
	DWORD cbEncodedBlob;
	BYTE* pbEncodedBlob;
	HCRYPTMSG hMsg;
	DWORD dwKeySpec;

	CRYPT_VERIFY_MESSAGE_PARA msgPara;

	msgPara.cbSize = sizeof ( CRYPT_VERIFY_MESSAGE_PARA );
	msgPara.dwMsgAndCertEncodingType = encoding;
	msgPara.hCryptProv = NULL;
	msgPara.pfnGetSignerCertificate = NULL;
	msgPara.pvGetArg = NULL;


	if ( CryptVerifyDetachedMessageSignature ( &msgPara, 0, sign->pbData, sign->cbData, 1, &pbContent, &cbContent, NULL ) ) {
		return true;
	} else {
		return false;
	}
}

Store::Store ( wstring name, LPCSTR StoreProvider, HCRYPTPROV_LEGACY CryptProvider ) {
	if ( !( store = CertOpenStore ( StoreProvider, 0, NULL, CryptProvider, name.c_str () ) ) ) {
		throw CertificateException ( L"The store was not opened." );
	}
}

shared_ptr<Certificate> Store::Find ( wstring name, DWORD encoding, DWORD findType ) {
	PCCERT_CONTEXT context;
	if ( !( context = CertFindCertificateInStore ( store, encoding, 0, findType, name.c_str (), NULL ) ) ) {
		throw CertificateException ( L"Signer certificate not found" );
	}

	return shared_ptr<Certificate> ( new Certificate ( context ) );
}

shared_ptr<Store> Store::Open ( wstring name, LPCSTR storeProvider, HCRYPTPROV_LEGACY cryptProvider ) {
	return shared_ptr<Store> ( new Store ( name, storeProvider, cryptProvider ) );
}