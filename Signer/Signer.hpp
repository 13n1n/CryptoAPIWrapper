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

using std::map;
using std::wstring;
using std::shared_ptr;

class Exception;
class CertificateException;
class Store;
class Certificate;


typedef CRYPT_DATA_BLOB DataBlob;
typedef std::_Tree_iterator<std::_Tree_val<std::_Tree_simple_types<std::pair<const wstring, DataBlob>>>> CertProperty;

class BlobPrinter {
	DataBlob data;
	wstring name;
public:
	BlobPrinter ( wstring name, DataBlob data );

	friend std::wostream& operator<< ( std::wostream&, const BlobPrinter& );
};

class Win32Exception {
	wstring message;
public:
	Win32Exception ( const wstring messageArg = L"" );

	const wstring what () {
		return message;
	}
};

class CertificateException: public Win32Exception {
public:
	CertificateException ( wstring message ): Win32Exception ( message ) {}
};

class Certificate {
public:
	static DWORD DISPLAY_TYPE;

private:
	wstring store;
	wstring name;
	PCCERT_CONTEXT context;

	map<wstring, DataBlob> properties;

public:
	const map<wstring, DataBlob> Properties () {
		return properties;
	}

	Certificate ( PCCERT_CONTEXT context );
	~Certificate () { CertFreeCertificateContext ( context ); }
	const wstring& Name () { return name; }
	CertProperty begin () { return properties.begin (); }
	CertProperty end () { return properties.end (); }

	void List ();
	DataBlob Sign ( DataBlob blob,
		DWORD encoding = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		LPSTR algo = szOID_RSA_SHA1RSA );
	bool Verify ( DataBlob* sign,
		DataBlob* message,
		DWORD encoding = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING );
};

class Store {
	HCERTSTORE store;

	Store ( wstring name,
		LPCSTR StoreProvider = CERT_STORE_PROV_SYSTEM_W,
		HCRYPTPROV_LEGACY CryptProvider = CERT_SYSTEM_STORE_CURRENT_USER );
public:
	class Iterator;
	friend Iterator;
	friend Certificate;

	class Iterator {
		PCCERT_CONTEXT context;
		Store *store;

	public:
		Iterator ( PCCERT_CONTEXT context, Store& store ) {
			this->context = context;
			this->store = &store;
		}
		 
		Iterator& operator ++ ( ) {
			context = CertEnumCertificatesInStore ( store->store, context );
			return *this;
		}

		bool operator == (const Iterator &rhs) { return this->context == rhs.context; }

		bool operator != ( const Iterator &rhs ) { return this->context != rhs.context; }

		Certificate* operator* ( ) { return new Certificate ( context ); }
	};
	
	~Store () { CertCloseStore ( store, 0 ); }

	Iterator begin () {
		return Iterator ( CertEnumCertificatesInStore ( store, NULL ), *this );
	}

	const Iterator end () { return Iterator ( NULL, *this ); }

	shared_ptr<Certificate> Find ( wstring name,
		DWORD encoding = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		DWORD findType = CERT_FIND_SUBJECT_STR );

	static shared_ptr<Store> Open ( wstring name,
		LPCSTR storeProvider = CERT_STORE_PROV_SYSTEM_W,
		HCRYPTPROV_LEGACY cryptProvider = CERT_SYSTEM_STORE_CURRENT_USER );
};