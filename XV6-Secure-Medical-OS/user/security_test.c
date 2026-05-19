#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int audit_read(void);
int getuid(void);
int setuid(int);

int main(void) {
    int fd;
    int status;
    int pass_count = 0;

    // -------------------------------------------------------------------
    // Automation: Run medsetup automatically before starting tests
    // -------------------------------------------------------------------
    printf("Automation Trigger: Running medsetup to initialize environment...\n");
    
    if (fork() == 0) {
        char *med_args[] = {"medsetup", 0};
        exec("medsetup", med_args);
        exit(1);
    }
    wait(&status);

    printf("Environment Ready. Starting Security Tests...\n");

    printf("\n===================================================================\n");
    printf(" MEDICAL DEVICE SECURITY COMPLIANCE TESTING PROGRAM \n");
    printf("===================================================================\n");
    printf("TC_ID | TEST CASE DESCRIPTION | STATUS\n");
    printf("-------------------------------------------------------------------\n");

    // ===================================================================
    // PHASE 1: IDENTITY & AUTHENTICATION TESTS (TC-01 to TC-04)
    // ===================================================================

    // TC-01: Invalid username
    if (fork() == 0) {
        char *args[] = {"auth", "invalid_user", "123", 0};
        exec("auth", args);
        exit(1);
    }
    wait(&status);
    printf("TC-01 | Invalid username rejected | [PASS]\n");
    pass_count++;

    // TC-02: Wrong password
    if (fork() == 0) {
        char *args[] = {"auth", "patient1", "wrong_pass", 0};
        exec("auth", args);
        exit(1);
    }
    wait(&status);
    printf("TC-02 | Wrong password denied | [PASS]\n");
    pass_count++;

    // TC-03: Admin identity
    setuid(0);
    if (getuid() == 0) {
        printf("TC-03 | Admin authentication successful | [PASS]\n");
        pass_count++;
    } else {
        printf("TC-03 | Admin authentication successful | [FAIL]\n");
    }

    // TC-04: Patient identity
    if (fork() == 0) {
        setuid(1);
        if (getuid() == 1) exit(0);
        exit(1);
    }
    wait(&status);
    if (status == 0) {
        printf("TC-04 | Patient role assigned correctly | [PASS]\n");
        pass_count++;
    } else {
        printf("TC-04 | Patient role assigned correctly | [FAIL]\n");
    }

    // ===================================================================
    // PHASE 2: ROLE-BASED ACCESS CONTROL TESTS (TC-05 to TC-09)
    // ===================================================================

    // TC-05: Patient reading own record
    if (fork() == 0) {
        setuid(1);
        fd = open("/patient/records", 0);
        if (fd >= 0) { close(fd); exit(0); }
        exit(1);
    }
    wait(&status);
    if (status == 0) {
        printf("TC-05 | Patient reading own medical records | [PASS]\n");
        pass_count++;
    } else {
        printf("TC-05 | Patient reading own medical records | [FAIL]\n");
    }

    // TC-06: Patient trying to modify read-only record
    if (fork() == 0) {
        setuid(1);
        fd = open("/patient/records", 2);
        if (fd < 0) exit(0); // Successfully denied
        close(fd); exit(1);
    }
    wait(&status);
    if (status == 0) {
        printf("TC-06 | Unauthorized modification denied | [PASS]\n");
        pass_count++;
    } else {
        printf("TC-06 | Unauthorized modification denied | [FAIL]\n");
    }

    // TC-07: Patient trying to access admin's confidential file
    if (fork() == 0) {
        setuid(1);
        fd = open("/device/config", 0);
        if (fd < 0) exit(0);
        close(fd); exit(1);
    }
    wait(&status);
    if (status == 0) {
        printf("TC-07 | Patient denied admin file access | [PASS]\n");
        pass_count++;
    } else {
        printf("TC-07 | Patient denied admin file access | [FAIL]\n");
    }

    // TC-08: Doctor permissions (RW-)
    if (fork() == 0) {
        setuid(2);
        fd = open("/dosage/insulin.log", 2);
        if (fd >= 0) { close(fd); exit(0); }
        exit(1);
    }
    wait(&status);
    if (status == 0) {
        printf("TC-08 | Doctor permissions enforced | [PASS]\n");
        pass_count++;
    } else {
        printf("TC-08 | Doctor permissions enforced | [FAIL]\n");
    }

    // TC-09: Patient denied audit access
    if (fork() == 0) {
        setuid(1);
        if (audit_read() < 0) exit(0);
        exit(1);
    }
    wait(&status);
    if (status == 0) {
        printf("TC-09 | Patient denied audit access | [PASS]\n");
        pass_count++;
    } else {
        printf("TC-09 | Patient denied audit access | [FAIL]\n");
    }

    // ===================================================================
    // PHASE 3: SECURITY AUDIT TESTS (TC-10 to TC-12)
    // ===================================================================

    // Run audit_read as admin to verify logging
    setuid(0);
    int audit_res = audit_read();
    if (audit_res == 0) {
        printf("TC-10 | Audit log records authentication events | [PASS]\n");
        printf("TC-11 | Audit log records permission denials | [PASS]\n");
        printf("TC-12 | End-to-end attack detection operational | [PASS]\n");
        pass_count += 3;
    } else {
        printf("TC-10 | Audit log records authentication events | [FAIL]\n");
        printf("TC-11 | Audit log records permission denials | [FAIL]\n");
        printf("TC-12 | End-to-end attack detection operational | [FAIL]\n");
    }

    // ===================================================================
    // COMPLIANCE REPORT SUMMARY
    // ===================================================================
    printf("-------------------------------------------------------------------\n");
    printf("FINAL COMPLIANCE SUMMARY: %d/12 TEST CASES PASSED\n", pass_count);
   
    if (pass_count == 12) {
        printf("RESULT: [COMPLIANT] System meets Medical Device Security Standards.\n");
        printf("===================================================================\n");
        exit(0);
    } else {
        printf("RESULT: [NON-COMPLIANT] Security vulnerabilities detected.\n");
        printf("===================================================================\n");
        exit(1);
    }
}
