/*
 * look through the file system to see what we have access to.
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>


typedef struct __stru_entry {
    const char *path;
    struct stat statbuf;
} entry_t;

typedef struct __stru_entries {
    unsigned int len;
    unsigned int idx;
    entry_t *head;
} entries_t;


entries_t writable = { 0, 0, NULL };
entries_t readable = { 0, 0, NULL };
entries_t suid = { 0, 0, NULL };
entries_t sgid = { 0, 0, NULL };
entries_t executable = { 0, 0, NULL };


void
perror_str(const char *fmt, ...)
{
    char *ptr = NULL;
    va_list vl;

    va_start(vl, fmt);
    if (vasprintf(&ptr, fmt, vl) == -1) {
        perror(fmt);
        return;
    }
    perror(ptr);
    free(ptr);
}


void
report_findings(const char *name, entries_t *pentries)
{
    unsigned int i;

    printf("[*] Found %u entries that are %s\n", pentries->idx, name);
    for (i = 0; i < pentries->idx; i++) {
        printf("    %s\n", pentries->head[i].path);
    }
}


int
is_executable(struct stat *sb)
{
    return (sb->st_mode & S_IXOTH);
}


int
is_setuid(struct stat *sb)
{
    return (is_executable(sb) && (sb->st_mode & S_ISUID));
}


int
is_setgid(struct stat *sb)
{
    return (is_executable(sb) && (sb->st_mode & S_ISGID));
}


int
is_writable(struct stat *sb)
{
    return (sb->st_mode & S_IWOTH);
}


int
is_readable(struct stat *sb)
{
    return (sb->st_mode & S_IROTH);
}


void
record_access(entries_t *pentries, const char *path, struct stat *sb)
{
    unsigned int new_next_idx = pentries->idx + 1;
    entry_t *pentry;

    if (new_next_idx > pentries->len) {
        entry_t *new_head;
        /* grow array */
        // XXX: TODO: optimize allocations
        new_head = (entry_t *)realloc(pentries->head, (pentries->len + 1) * sizeof(entry_t));
        if (!new_head) {
            fprintf(stderr, "[!] Out of memory!\n");
            exit(1);
        }
        pentries->head = new_head;
        pentries->len++;
    }

    pentry = pentries->head + pentries->idx;
    pentries->idx = new_next_idx;
    pentry->path = strdup(path);
    memcpy(&(pentry->statbuf), sb, sizeof(pentry->statbuf));
}


/*
 * filter the permissions we have on the entry into buckets
 */
void
record_access_level(const char *path, struct stat *sb)
{
    if (is_setuid(sb))
        record_access(&suid, path, sb);
    else if (is_setgid(sb))
        record_access(&sgid, path, sb);
    else if (is_writable(sb))
        record_access(&writable, path, sb);
#ifdef RECORD_LESS_INTERESTING
    else if (is_readable(sb))
        record_access(&readable, path, sb);
    else if (is_executable(sb))
        record_access(&executable, path, sb);
#endif
}


char *my_stpcpy(char *dst, char *src)
{
    char *q = dst, *p = src;

    while (*p)
        *q++ = *p++;
    return q;
}


void
scan_directory(const char *dir)
{
    DIR *pd;
    struct dirent *pe;
    char canonical_path[PATH_MAX+1] = { 0 };
    char *end;
    struct stat sb;

    if (!(pd = opendir(dir))) {
        perror_str("[!] Unable to open dir \"%s\"", dir);
        return;
    }

    while ((pe = readdir(pd))) {
        if (pe->d_name[0] == '.') {
            if (pe->d_name[1] == '\0')
                continue;
            if (pe->d_name[1] == '.' && pe->d_name[2] == '\0')
                continue;
        }

        end = my_stpcpy(canonical_path, dir);
        if (end - canonical_path >= PATH_MAX - 1 - strlen(pe->d_name)) {
            fprintf(stderr, "[!] name too long \"%s/%s\"\n", dir, pe->d_name);
            continue;
        }
        if (end > canonical_path && *(end - 1) != '/')
            *end++ = '/';
        strcpy(end, pe->d_name);

#ifdef DEBUG
        printf("[*] checking: 0x%x 0x%x 0x%x 0x%x %s ...\n", 
               (unsigned int)pe->d_ino, (unsigned int)pe->d_off,
               pe->d_reclen,
               pe->d_type, canonical_path);
#endif

        /* decide where to put this one */
        if (lstat(canonical_path, &sb) == -1) {
            perror_str("[!] Unable to lstat \"%s\"", canonical_path);
            continue;
        }

        /* skip symlinks.. */
        if (S_ISLNK(sb.st_mode))
            continue;

        record_access_level(canonical_path, &sb);

        /* can the child directory too */
        if (pe->d_type == DT_DIR)
            scan_directory(canonical_path);
    }

    closedir(pd);
}


int
main(int c, char *v[])
{
    char canonical_path[PATH_MAX+1] = { 0 };
    int i;

    for (i = 1; i < c; i++) {
        if (!realpath(v[i], canonical_path)) {
            perror_str("[!] Unable to resolve path \"%s\"", v[i]);
            return 1;
        }

        scan_directory(canonical_path);
    }

    /* report the findings */
    report_findings("set-uid executable", &suid);
    report_findings("set-gid executable", &sgid);
    report_findings("writable", &writable);
#ifdef RECORD_LESS_INTERESTING
    report_findings("readable", &readable);
    report_findings("only executable", &executable);
#endif

    return 0;
}
