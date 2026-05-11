// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Prerequisites:
//    Check readme.md for prerequisites to run this sample.
//
// This sample demonstrates the AziHSM in the following scenario:
//
// 1. Import an RSA key into the AziHSM by performing Secure Key Release with Azure Key Vault and Microsoft Azure Attestation.
// 2. Use the imported RSA key to encrypt data.
// 3. Use the imported RSA key to decrypt data.
//
// Several helper functions are defined below; these contain the specifics of
// the NCrypt API calls. To see the high-level set of steps in this scenario,
// please study the `main` function.

// Silence warning from rapidjson for C++ 17
#define _SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING

#include <iostream>
#include <vector>
#include <string>

#include <Windows.h>
#include <ncrypt.h>

#include <wil/resource.h>
#include <wil/result.h>

#include <curl/curl.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <cppcodec/base64_url_unpadded.hpp>

// Header file of AziHSM SDK, see cpp\include\AziHSM\README.md for details
#include "AziHSM/AziHSM.h"
// Header file of Guest Attestation Library, see readme.md for details
#include <AziHSMAttestationApi.h>

#include "Utils/CryptoUtils.h"

//////////////////////////
// Forward Declarations //
//////////////////////////

// The Full Secure Key Release Flow Reference
//
// hProvider: Handle to the opened AZIHSM provider
// hImportKey: Handle to the built-in import/wrapping key in AZIHSM
// payload: A string representing JSON object, contains the claims to be included in MAA token. This will be passed to MAA as the "claims" when attesting the imported key.
// maaEndpoint: The MAA endpoint URL. For example, "https://mytenant.attest.azure.net"
// keyUrl: The URL of the key in Azure Key Vault. For example, "https://myvault.vault.azure.net/keys/mykey/12345678-1234-1234-1234-123456789abc"
// clientId: Optional Azure Identity Client ID that has access to the AKV, used when the VM has multiple user assigned managed identities.
// keyType: the imported key is RSA or ECDSA
// keyUsage: can be one of:
//     NCRYPT_ALLOW_DECRYPT_FLAG: Allow Encrypt/Decrypt
//     NCRYPT_ALLOW_SIGNING_FLAG: Allow Sign/Verify
//     NCRYPT_ALLOW_KEY_IMPORT_FLAG: Allow importing keys
// outHImportedKey: The handle to the released/imported key in AZIHSM after successful secure key release
HRESULT secure_key_release(
    _In_ const NCRYPT_PROV_HANDLE &hProvider,
    _In_ const NCRYPT_KEY_HANDLE &hImportKey,
    _In_ const std::string &payload,
    _In_ const std::string &maaEndpoint,
    _In_ const std::string &keyUrl,
    _In_opt_z_ const char *clientId,
    _In_ const DWORD keyUsage,
    _Out_ wil::unique_ncrypt_key &outHImportedKey,
    _Out_ KeyType &outKeyType,
    _Out_ int &outKeySize);

// Some sample usage of the released/imported key
// Replace this with your workload
//
// hImportedKey: The handle to the released/imported key in AZIHSM
HRESULT test_imported_key(_In_ const NCRYPT_KEY_HANDLE &hImportedKey, _In_ const KeyType keyType, _In_ const int keySize);

//////////
// Main //
//////////
int main(_In_ int argc, _In_reads_(argc) char *argv[])
{
    try
    {
        set_wil_log_callback();

        // Check command line arguments
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " <MAA_ENDPOINT> <KEY_URL> [CLIENT_ID]" << std::endl;
            std::cerr << "  MAA_ENDPOINT: URL of Microsoft Azure Attestation endpoint" << std::endl;
            std::cerr << "  KEY_URL: URL to the key in Azure Key Vault" << std::endl;
            std::cerr << "  CLIENT_ID: Optional Azure Identity Client ID" << std::endl;
            return E_INVALIDARG;
        }

        const char *maaEndpoint = argv[1];
        const char *keyUrl = argv[2];
        const char *clientId = (argc > 3) ? argv[3] : nullptr;

        wil::unique_ncrypt_prov hProvider;
        wil::unique_ncrypt_key hImportKey;

        // Step 1: Open AZIHSM provider and get the import/wrapping key handle
        RETURN_IF_FAILED_MSG(open_provider_and_key(hProvider, hImportKey), "Failed open_provider_and_key");
        std::cout << "Done open_provider_and_key." << std::endl;

        // After performing Secure Key Release
        // This will be the handle to the released/imported key
        wil::unique_ncrypt_key hImportedKey;
        KeyType keyType;
        // Size of Key, 2048...4096 for RSA, 256...521 for EC
        int keySize;

        // A String representing a JSON object
        // This will be passed to MAA as the "claims" when attesting
        // the imported key. You can include any information in the
        // payload that you want, and MAA will include the same payload
        // in the token after a successful attestation. In this sample
        // we just use a simple JSON object with one key-value pair,
        // but in real world application you can include more information
        // such as key metadata (e.g. key usage, key type, etc.) or any other custom claims.
        const char *payload = "{\"key\": \"value\"}";

        // Step 2: Perform the secure key release to get the released/imported key handle
        RETURN_IF_FAILED_MSG(secure_key_release(hProvider.get(), hImportKey.get(),
                                                payload, maaEndpoint, keyUrl, clientId, NCRYPT_ALLOW_SIGNING_FLAG,
                                                hImportedKey, keyType, keySize),
                             "Failed secure_key_release");
        std::cout << "Done secure_key_release" << std::endl;

        // Step 3: Simulate some workload
        RETURN_IF_FAILED_MSG(test_imported_key(hImportedKey.get(), keyType, keySize), "Failed test_imported_key");
        std::cout << "Done test_imported_key" << std::endl;

        return S_OK;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Unhandled exception in SECURE-KEY-RELEASE sample: " << ex.what() << std::endl;
        return E_FAIL;
    }
    catch (...)
    {
        std::cerr << "Unhandled unknown exception in SECURE-KEY-RELEASE sample" << std::endl;
        return E_FAIL;
    }
}

/////////////
// Helper //
////////////

// Helper structure for libcurl HTTP response
struct HttpResponse
{
    std::string data;
    long response_code = 0;
};

// Callback function for libcurl to write response data
size_t WriteCallback(_In_reads_bytes_(size *nmemb) void *contents, _In_ size_t size, _In_ size_t nmemb, _Inout_ void *userp)
{
    size_t totalSize = size * nmemb;
    if (userp == nullptr || (contents == nullptr && totalSize != 0))
    {
        return 0;
    }

    HttpResponse *response = static_cast<HttpResponse *>(userp);
    response->data.append((char *)contents, totalSize);
    return totalSize;
}

// Callback function for Guest Attestation Library logger
static void CustomLog(_In_opt_ void *ctx,
                      _In_z_ const char *log_tag,
                      _In_ LogLevel level,
                      _In_z_ const char *function,
                      _In_ const int line,
                      _In_z_ const char *msg)
{
    std::string LogLevelStrings[4] = {"Error", "Warn", "Info", "Debug"};
    struct MyCustomData *customData = (struct MyCustomData *)ctx;

    printf("Level: %s Tag: %s %s:%d:%s\n", LogLevelStrings[static_cast<int>(level)].c_str(), log_tag, function, line, msg);
}

// TODO: You should generate random nonce
// For simplicity, a fixed nonce is used here
std::string generate_nonce()
{
    std::cerr << "DO NOT USE FOR PRODUCTION: generate_nonce used a fixed nonce. " << std::endl;
    // Nonce can be a short string with random characters
    return "FIXED_NONCE";
}

// Return a copy of s, converted to lower case
std::string to_lower_ascii(_In_ const std::string &s)
{
    std::string s_copy(s);
    std::transform(s_copy.begin(), s_copy.end(), s_copy.begin(),
                   [](unsigned char ch)
                   { return static_cast<char>(std::tolower(ch)); });
    return s_copy;
}

bool starts_with(_In_ const std::string &str, _In_ const std::string &prefix)
{
    std::string str_lower = to_lower_ascii(str);
    std::string prefix_lower = to_lower_ascii(prefix);
    return str_lower.size() >= prefix_lower.size() &&
           str_lower.compare(0, prefix_lower.size(), prefix_lower) == 0;
}

///////////////////
// SKR utilities //
///////////////////

// Make a HTTP GET Request to get IMDS token for AKV
// See more about IMDS endpoint: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
// Return the token string upon success
// Same as:
// curl --location 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' \
// --header 'Metadata: true'
AZIHSM_STATUS call_imds_token(_In_opt_z_ const char *clientId, _Out_ std::string &outToken)
{
    outToken.clear();

    // Construct IMDS URL
    std::string url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net";
    if (clientId && strlen(clientId) > 0)
    {
        url += "&client_id=" + std::string(clientId);
    }

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        std::cerr << "Failed to initialize curl for IMDS request" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    HttpResponse response;
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Metadata: true");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.response_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || response.response_code != 200)
    {
        std::cerr << "IMDS request failed. Code: " << response.response_code << ", Error: " << curl_easy_strerror(res) << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }
    if (response.data.empty())
    {
        std::cerr << "IMDS response payload is empty" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    // Parse JSON response using rapidjson
    // response should be a JSON string like
    // {"access_token": "xyz"}
    rapidjson::Document doc;
    doc.Parse(response.data.c_str());

    if (doc.HasParseError() || !doc.HasMember("access_token") || !doc["access_token"].IsString())
    {
        std::cerr << "Failed to parse access_token from IMDS response" << std::endl;
        std::cerr << "Original IMDS response: " << response.data << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    outToken = doc["access_token"].GetString();
    return AZIHSM_STATUS::AZIHSM_SUCCESS;
}

// Parse AKV JWT response and extract key blob
// For simplicity, SKIPPED JWT verification
// Return the wrapped key blob upon success
// TODO: you should replace this with a proper JWT parsing and verification in production code
AZIHSM_STATUS parse_akv_jwt(_In_ const std::string &jwtResponse,
                            _Out_ std::vector<uint8_t> &outKeyBlob, _Out_ KeyType &outKeyType, _Out_ int &outKeySize)
{
    outKeyBlob.clear();
    outKeySize = -1;

    if (jwtResponse.empty())
    {
        std::cerr << "AKV JWT response is empty" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    std::cerr << "DO NOT USE FOR PRODUCTION: parse_akv_jwt skipped JWT verification. " << std::endl;
    // Simple JWT parsing: split by '.' and parse JSON body without checking header/signature
    size_t firstDot = jwtResponse.find('.');
    size_t secondDot = jwtResponse.find('.', firstDot + 1);
    if (firstDot == std::string::npos || secondDot == std::string::npos)
    {
        std::cerr << "Invalid JWT format in AKV response" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    std::string payloadB64 = jwtResponse.substr(firstDot + 1, secondDot - firstDot - 1);

    // Decode base64 payload using cppcodec
    std::vector<uint8_t> decodedPayload;
    try
    {
        decodedPayload = cppcodec::base64_url_unpadded::decode(payloadB64);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Payload Base64 decode error: " << e.what() << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    std::string payloadStr(decodedPayload.begin(), decodedPayload.end());

    // Parse JWT payload JSON
    rapidjson::Document jwtDoc;
    jwtDoc.Parse(payloadStr.c_str());

    if (jwtDoc.HasParseError())
    {
        std::cerr << "Failed to parse JWT payload JSON" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    // Navigate to response.key.key.key_hsm.ciphertext and extract the base64-encoded ciphertext
    if (!jwtDoc.HasMember("response") || !jwtDoc["response"].IsObject())
    {
        std::cerr << "JWT payload missing 'response' field" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    const auto &responseObj = jwtDoc["response"];
    if (!responseObj.HasMember("key") || !responseObj["key"].IsObject())
    {
        std::cerr << "JWT payload missing 'response.key' field" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    const auto &keyObj = responseObj["key"];
    if (!keyObj.HasMember("key") || !keyObj["key"].IsObject())
    {
        std::cerr << "JWT payload missing 'response.key.key' field" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    const auto &innerKeyObj = keyObj["key"];
    if (!innerKeyObj.HasMember("key_hsm") || !innerKeyObj["key_hsm"].IsString())
    {
        std::cerr << "JWT payload missing 'response.key.key.key_hsm' field" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    // Obtained Key HSM Blob at claim.response.key.key.key_hsm
    std::string keyHsmB64 = innerKeyObj["key_hsm"].GetString();

    if (!innerKeyObj.HasMember("kty") || !innerKeyObj["kty"].IsString())
    {
        std::cerr << "JWT payload missing 'response.key.key.kty' field" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    // Obtained Key Type at claim.response.key.key.kty
    std::string kty = innerKeyObj["kty"].GetString();
    KeyType keyType;
    if (starts_with(kty, "rsa"))
    {
        keyType = KeyType::KEY_TYPE_RSA;
    }
    else
    {
        keyType = KeyType::KEY_TYPE_ECDSA;
    }

    int keySize = -1;

    if (keyType == KeyType::KEY_TYPE_RSA)
    {
        if (!keyObj.HasMember("attributes") || !keyObj["attributes"].IsObject())
        {
            std::cerr << "JWT payload missing 'response.key.attributes' field" << std::endl;
            return AZIHSM_STATUS::AZIHSM_FAILURE;
        }

        const auto &attributesObj = keyObj["attributes"];
        if (!attributesObj.HasMember("key_size") || !attributesObj["key_size"].IsInt())
        {
            std::cerr << "JWT payload missing 'response.key.attributes.key_size' field" << std::endl;
            return AZIHSM_STATUS::AZIHSM_FAILURE;
        }

        // Obtained Key Size for RSA Key at claim.response.key.attributes.key_size
        keySize = attributesObj["key_size"].GetInt();
    }
    else
    {
        if (!innerKeyObj.HasMember("crv") || !innerKeyObj["crv"].IsString())
        {
            std::cerr << "JWT payload missing 'response.key.key.crv' field" << std::endl;
            return AZIHSM_STATUS::AZIHSM_FAILURE;
        }
        std::string crv = innerKeyObj["crv"].GetString();

        // Obtained Key Size for EC Key at claim.response.key.key.crv
        if (crv == "P-256")
        {
            keySize = 256;
        }
        else if (crv == "P-384")
        {
            keySize = 384;
        }
        else if (crv == "P-521")
        {
            keySize = 521;
        }
        else
        {
            std::cerr << "Invalid response.key.key.crv field: " << crv << std::endl;
            return AZIHSM_STATUS::AZIHSM_FAILURE;
        }
    }

    // Decode key_hsm base64 to get the nested JSON
    std::vector<uint8_t> keyHsmData;
    try
    {
        keyHsmData = cppcodec::base64_url_unpadded::decode(keyHsmB64);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Key HSM Base64 decode error: " << e.what() << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    std::string keyHsmStr(keyHsmData.begin(), keyHsmData.end());

    rapidjson::Document keyHsmDoc;
    keyHsmDoc.Parse(keyHsmStr.c_str());

    if (keyHsmDoc.HasParseError() || !keyHsmDoc.HasMember("ciphertext") || !keyHsmDoc["ciphertext"].IsString())
    {
        std::cerr << "Failed to extract ciphertext from key_hsm data" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    std::string ciphertextB64 = keyHsmDoc["ciphertext"].GetString();
    std::vector<uint8_t> keyBlob;
    try
    {
        keyBlob = cppcodec::base64_url_unpadded::decode(ciphertextB64);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Ciphertext Base64 decode error: " << e.what() << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    outKeyBlob = std::move(keyBlob);
    outKeyType = keyType;
    outKeySize = keySize;

    return AZIHSM_STATUS::AZIHSM_SUCCESS;
}

// Make a HTTP POST request to Azure Key Vault key release API
// Return the JWT from AKV that contains wrapped key blob
// Same as:
// curl --location '<key_url>/release?api-version=7.3' \
// --header 'Content-Type: application/json' \
// --header 'Authorization: Bearer <imds_token>' \
// --data '{
//     "nonce": "<random_nonce>",
//     "target": "<maa_token>",
//     "enc": "CKM_RSA_AES_KEY_WRAP"
// }'
AZIHSM_STATUS call_akv_key_release(_In_ const std::string &keyUrl, _In_ const std::string &accessToken, _In_ const std::string &maaToken, _Out_ std::string &outJwt)
{
    outJwt.clear();

    if (keyUrl.empty() || accessToken.empty() || maaToken.empty())
    {
        std::cerr << "AKV request inputs must not be empty" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    std::string nonce = generate_nonce();

    // Build release URL
    std::string releaseUrl = keyUrl;
    if (releaseUrl.find("/release") == std::string::npos)
    {
        if (releaseUrl.back() == '/')
        {
            releaseUrl.pop_back();
        }
        releaseUrl += "/release?api-version=7.3";
    }

    // Build JSON object
    // {"nonce": "<nonce>", "target": "<MAA Token>", "enc": "CKM_RSA_AES_KEY_WRAP"}
    rapidjson::Document payload;
    payload.SetObject();
    rapidjson::Document::AllocatorType &allocator = payload.GetAllocator();

    payload.AddMember("nonce", rapidjson::Value(nonce.c_str(), allocator), allocator);
    payload.AddMember("target", rapidjson::Value(maaToken.c_str(), allocator), allocator);
    payload.AddMember("enc", "CKM_RSA_AES_KEY_WRAP", allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    payload.Accept(writer);
    std::string jsonStr = buffer.GetString();

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        std::cerr << "Failed to initialize curl for AKV request" << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    HttpResponse response;
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string authHeader = "Authorization: Bearer " + accessToken;
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, releaseUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonStr.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.response_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || response.response_code != 200)
    {
        std::cerr << "AKV request failed. Code: " << response.response_code << ", Error: " << curl_easy_strerror(res) << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    // Parse JSON response using rapidjson
    // Expect response is a JSON string like
    // {"value": "<JWT>"}
    rapidjson::Document doc;
    doc.Parse(response.data.c_str());

    if (doc.HasParseError() || !doc.HasMember("value") || !doc["value"].IsString())
    {
        std::cerr << "Failed to parse value field from AKV response" << std::endl;
        std::cerr << "Original AKV response: " << response.data << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    outJwt = doc["value"].GetString();

    return AZIHSM_STATUS::AZIHSM_SUCCESS;
}

// Call Guest Attestation Library to attest the key with MAA
// MAA will return a JWT upon success
AZIHSM_STATUS attest_import_key(
    _In_ const NCRYPT_KEY_HANDLE &hImportKey,
    _In_ const std::string &maaEndpoint,
    _In_ const std::string &payload,
    _Out_ std::string &outMaaToken)
{
    outMaaToken.clear();
    if (hImportKey == 0 || maaEndpoint.empty() || payload.empty())
    {
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    char *attestationToken = nullptr;

    long result;

    // Initialize Attestation Library
    AttestationLogInfo logger;
    logger.Log = &CustomLog;
    logger.Ctx = nullptr;
    result = InitAttestationLib(&logger);
    if (result != 0)
    {
        std::cerr << "Failed InitAttestationLib: Error code = " << result << std::endl;
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    // Call the Guest Attestation Library to attest the key with MAA
    result = AttestAziHsm(
        maaEndpoint.c_str(),
        nullptr,
        payload.c_str(),
        hImportKey,
        &attestationToken,
        "azihsm-sample-client");

    if (result != 0)
    {
        std::cerr << "Failed AttestAziHsm: Error code = " << result << std::endl;
        UninitAttestationLib();
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    if (attestationToken == nullptr)
    {
        std::cerr << "Unexpected! AttestAziHsm returned success but attestation token is null" << std::endl;
        UninitAttestationLib();
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    // Copy the token to output string
    outMaaToken = std::string(attestationToken);

    // Free the allocated buffer
    Free(attestationToken);
    UninitAttestationLib();

    return AZIHSM_STATUS::AZIHSM_SUCCESS;
}

// Call Azure Key Vault to release the key in vault
// Return the wrapped key blob upon success
AZIHSM_STATUS release_key(
    _In_ const std::string &keyUrl,
    _In_ const std::string &maaToken,
    _In_opt_z_ const char *clientId,
    _Out_ std::vector<uint8_t> &outKeyBlob,
    _Out_ KeyType &outKeyType,
    _Out_ int &outKeySize)
{
    if (keyUrl.empty() || maaToken.empty())
    {
        return AZIHSM_STATUS::AZIHSM_FAILURE;
    }

    // Step 1: Call IMDS to obtain access token
    std::string imdsToken;
    AZIHSM_STATUS status = call_imds_token(clientId, imdsToken);
    if (status != AZIHSM_STATUS::AZIHSM_SUCCESS)
    {
        return status;
    }

    // Step 2: Call AKV key release API
    std::string jwt;
    status = call_akv_key_release(keyUrl, imdsToken, maaToken, jwt);
    if (status != AZIHSM_STATUS::AZIHSM_SUCCESS)
    {
        return status;
    }

    // Step 3: Parse the JWT to get key blob, type and size
    return parse_akv_jwt(jwt, outKeyBlob, outKeyType, outKeySize);
}

// Import the key blob from Azure Key Vault into AziHSM
// The key blob is expected to be in PKCS#11 RSA AES wrap format
//
// hProvider: Handle to the opened AZIHSM provider
// hImportKey: Handle to the built-in import/wrapping key in AZIHSM
// keyBlob: The wrapped key blob obtained from Azure Key Vault
// keyType: the imported key is RSA or ECDSA
// keyUsage: can be one of:
//     NCRYPT_ALLOW_DECRYPT_FLAG: Allow Encrypt/Decrypt
//     NCRYPT_ALLOW_SIGNING_FLAG: Allow Sign/Verify
//     NCRYPT_ALLOW_KEY_IMPORT_FLAG: Allow importing keys
// outHImportedKey: The handle to the released/imported key in AZIHSM after successful import
HRESULT import_key_blob(
    _In_ const NCRYPT_PROV_HANDLE &hProvider,
    _In_ const NCRYPT_KEY_HANDLE &hImportKey,
    _In_ const std::vector<uint8_t> &keyBlob,
    _In_ const DWORD keyUsage,
    _In_ const KeyType keyType,
    _In_ const int keySize,
    _Out_ wil::unique_ncrypt_key &outHImportedKey)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, hProvider == 0 || hImportKey == 0, "Invalid provider/import key handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, keyBlob.empty(), "Wrapped key blob must not be empty");

    // Construct PKCS#11 blob structure
    BCRYPT_PKCS11_RSA_AES_WRAP_BLOB blobHeader = {};
    blobHeader.dwMagic = BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC;
    blobHeader.cbKey = static_cast<DWORD>(keyBlob.size());
    // AKV uses SHA-1
    blobHeader.cbPaddingAlgId = static_cast<DWORD>((wcslen(NCRYPT_SHA1_ALGORITHM) + 1) * sizeof(wchar_t));
    blobHeader.cbPaddingLabel = 0; // Empty padding label

    // Calculate total blob size
    size_t totalSize = sizeof(blobHeader) + keyBlob.size() + blobHeader.cbPaddingAlgId;
    std::vector<uint8_t> fullBlob(totalSize);

    // Copy data to full blob
    uint8_t *pData = fullBlob.data();
    memcpy(pData, &blobHeader, sizeof(blobHeader));
    pData += sizeof(blobHeader);
    memcpy(pData, keyBlob.data(), keyBlob.size());
    pData += keyBlob.size();
    memcpy(pData, NCRYPT_SHA1_ALGORITHM, blobHeader.cbPaddingAlgId);

    RETURN_IF_FAILED_MSG(
        import_bcrypt_wrapped_key(hProvider, hImportKey, fullBlob.data(), (DWORD)fullBlob.size(), keyType, keySize, keyUsage, outHImportedKey),
        "Failed import_bcrypt_wrapped_key");

    return S_OK;
}

// The Full Secure Key Release Flow Reference
//
// hProvider: Handle to the opened AZIHSM provider
// hImportKey: Handle to the built-in import/wrapping key in AZIHSM
// payload: A string representing JSON object, contains the claims to be included in MAA token. This will be passed to MAA as the "claims" when attesting the imported key.
// maaEndpoint: The MAA endpoint URL. For example, "https://mytenant.attest.azure.net"
// keyUrl: The URL of the key in Azure Key Vault. For example, "https://myvault.vault.azure.net/keys/mykey/12345678-1234-1234-1234-123456789abc"
// clientId: Optional Azure Identity Client ID that has access to the AKV, used when the VM has multiple user assigned managed identities.
// keyUsage: can be one of:
//     NCRYPT_ALLOW_DECRYPT_FLAG: Allow Encrypt/Decrypt
//     NCRYPT_ALLOW_SIGNING_FLAG: Allow Sign/Verify
//     NCRYPT_ALLOW_KEY_IMPORT_FLAG: Allow importing keys
// outHImportedKey: The handle to the released/imported key in AZIHSM after successful secure key release
HRESULT secure_key_release(
    _In_ const NCRYPT_PROV_HANDLE &hProvider,
    _In_ const NCRYPT_KEY_HANDLE &hImportKey,
    _In_ const std::string &payload,
    _In_ const std::string &maaEndpoint,
    _In_ const std::string &keyUrl,
    _In_opt_z_ const char *clientId,
    _In_ const DWORD keyUsage,
    _Out_ wil::unique_ncrypt_key &outHImportedKey,
    _Out_ KeyType &outKeyType,
    _Out_ int &outKeySize)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, hProvider == 0 || hImportKey == 0, "Invalid provider/import key handle");
    RETURN_HR_IF_MSG(E_INVALIDARG, payload.empty() || maaEndpoint.empty() || keyUrl.empty(), "Secure key release inputs must not be empty");

    std::string maaToken;
    std::vector<uint8_t> keyBlob;

    // Step 1: Attest the AziHSM's import key with MAA and get the MAA token
    RETURN_HR_IF_MSG(E_FAIL,
                     AZIHSM_STATUS::AZIHSM_SUCCESS != attest_import_key(hImportKey, maaEndpoint, payload, maaToken),
                     "Failed attest_import_key");
    std::cout << "Done attest_import_key." << std::endl;

    // Step 2: Call Azure Key Vault to release the key, get the wrapped key blob
    KeyType keyType;
    int keySize;
    RETURN_HR_IF_MSG(E_FAIL,
                     AZIHSM_STATUS::AZIHSM_SUCCESS != release_key(keyUrl, maaToken, clientId, keyBlob, keyType, keySize),
                     "Failed release_key");
    std::cout << "Done release_key. wrapped key blob length: " << keyBlob.size()
              << ". Key type: " << (keyType == KeyType::KEY_TYPE_RSA ? "RSA" : "EC")
              << ". Key size: " << keySize << std::endl;

    // Step 3: Import the wrapped key into the AziHSM
    RETURN_IF_FAILED_MSG(import_key_blob(hProvider, hImportKey, keyBlob, keyUsage, keyType, keySize, outHImportedKey), "Failed import_key_blob");

    // Fill out params when everything is successful
    outKeyType = keyType;
    outKeySize = keySize;

    std::cout << "Done import_key_blob" << std::endl;

    return S_OK;
}

// Some sample usage of the released/imported key
// Replace this with your workload
//
// hImportedKey: The handle to the released/imported key in AZIHSM
HRESULT test_imported_key(_In_ const NCRYPT_KEY_HANDLE &hImportedKey, _In_ const KeyType keyType, _In_ const int keySize)
{
    RETURN_HR_IF_MSG(E_INVALIDARG, hImportedKey == 0, "Invalid imported key handle");

    // In production, you should hash the message
    // For this sample, we directly use message as hash result
    std::string message = "Hello, World!";

    // Not used
    std::vector<BYTE> sig;
    if (keyType == KeyType::KEY_TYPE_RSA)
    {
        RETURN_IF_FAILED_MSG(sign_verify_rsa(hImportedKey, 32, NCRYPT_SHA256_ALGORITHM, message, sig), "Failed sign_verify_rsa");
    }
    else
    {
        DWORD hashLen = -1;
        if (keySize == 256)
        {
            hashLen = 32;
        }
        else if (keySize == 384)
        {
            hashLen = 48;
        }
        else if (keySize == 521)
        {
            hashLen = 66;
        }
        else
        {
            RETURN_HR_MSG(E_FAIL, "Invalid Key Size for EC Key: %d", keySize);
        }
        RETURN_IF_FAILED_MSG(sign_verify_ecdsa(hImportedKey, hashLen, message, sig), "Failed sign_verify_ecdsa");
    }

    std::cout << "Done test workload. " << std::endl;
    return S_OK;
}
