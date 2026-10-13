#include <stdio.h>
#include <string.h>
#include "policy.h"

int load_policy(const char *filename, PolicyRule rules[], int *rule_count) {
    FILE *file = fopen(filename, "r");
    if (!file) { perror("Could not open policy file"); return -1; }

    char line[256];
    *rule_count = 0;
    while (fgets(line, sizeof(line), file)) {
        char syscall_name[32], action[16], extra[16];
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        int fields = sscanf(line, "%31s %15s %15s", syscall_name, action, extra);
        if (fields == 0) continue;
        if (fields != 2) {
            fprintf(stderr, "Invalid policy line: %s", line);
            fclose(file); return -1;
        }
        if (*rule_count >= MAX_RULES) {
            fprintf(stderr, "Too many policy rules (max %d).\\n", MAX_RULES);
            fclose(file); return -1;
        }
        if (strcmp(action, "allow") && strcmp(action, "deny")) {
            fprintf(stderr, "Unknown action '%s' for syscall '%s'.\\n", action, syscall_name);
            fclose(file); return -1;
        }
        strcpy(rules[*rule_count].syscall_name, syscall_name);
        rules[*rule_count].action = !strcmp(action, "allow") ? ACTION_ALLOW : ACTION_DENY;
        (*rule_count)++;
    }
    if (ferror(file)) { perror("Reading policy file"); fclose(file); return -1; }
    fclose(file);
    if (*rule_count == 0) {
        fprintf(stderr, "Policy file contains no rules.\\n");
        return -1;
    }
    return 0;
}
