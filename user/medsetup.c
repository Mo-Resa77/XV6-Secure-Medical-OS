#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

void print_status(char *file, char *owner, char *mode) {
    printf("%s\t\t%s\t\t%s\n", file, owner, mode);
}

int main() {
    printf("Initializing Medical OS Security Environment...\n");
    printf("Please wait...\n\n");

    // 1. Set correct permissions for fundamental tools
    char *binaries[] = {"sh", "cat", "ls", "echo", "auth" , "audit_read" };
    for(int i = 0; i < 6; i++) {
        char *args[] = {"chmod", "755", binaries[i], 0};
        if(fork() == 0) 
            exec("chmod", args);
        wait(0);
    }

    // 2. Create users (User Provisioning)
    char *u1[] = {"useradd", "patient1", "p123", "1", 0};
    if(fork() == 0) exec("useradd", u1);
    wait(0);

    char *u2[] = {"useradd", "doctor1", "d123", "2", 0};
    if(fork() == 0) exec("useradd", u2);
    wait(0);

    // 3. Prepare medical files with initial content
    int fd;

    fd = open("/patient/records", 0x200 | 0x002);   // O_CREATE | O_RDWR
    write(fd, "Private Patient Record v1.0\n", 28);
    close(fd);

    fd = open("/dosage/insulin.log", 0x200 | 0x002);
    write(fd, "Dose: 5mg Insulin\n", 18);
    close(fd);

    fd = open("/device/config", 0x200 | 0x002);
    write(fd, "System Confidential Config\n", 27);
    close(fd);

    // 4. Set ownership and permissions
    char *setup_cmds[][3] = {
        {"chown", "1", "/patient/records"}, 
        {"chmod", "400", "/patient/records"},
        {"chown", "2", "/dosage/insulin.log"}, 
        {"chmod", "644", "/dosage/insulin.log"},
        {"chown", "0", "/device/config"}, 
        {"chmod", "600", "/device/config"},
        {"chown", "0", "audit_read"},
        {"chmod", "755", "audit_read"}
    };

    for(int i = 0; i < 8; i++) {
        char *args[] = {setup_cmds[i][0], setup_cmds[i][1], setup_cmds[i][2], 0};
        if(fork() == 0) 
            exec(setup_cmds[i][0], args);
        wait(0);
    }

    // --- Security Setup Summary Report ---
    printf("\n====================================================\n");
    printf("FINAL SECURITY SETUP SUMMARY\n");
    printf("====================================================\n");
    printf("Users Created: patient1 (UID 1) -pass=p123 , doctor1 (UID 2) -pass=d123  \n");
    printf("------------------------------------------------------------------------\n");
    printf("File Path\t\tOwner UID\tPermissions\n");
    printf("----------------------------------------------------\n");

    print_status("/patient/records", "1 (Patient)", "400 (R--)");
    print_status("/dosage/insulin.log", "2 (Doctor) ", "644 (RW-)");
    print_status("/device/config", "0 (Admin)  ", "600 (RW-)");

    printf("====================================================\n");
    printf("Security Environment Ready for Testing!\n\n");

    exit(0);
}
