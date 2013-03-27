/*
 * look through the file system to see what we have access to.
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>


typedef struct __stru_entry {
    const char *path;
    struct stat statbuf;
} entry_t;

typedef struct __stru_entries {
    unsigned int len;
    unsigned int idx;
    entry_t *head;
} entries_t;


entries_t suid = { 0, 0, NULL };
entries_t sgid = { 0, 0, NULL };
entries_t writable = { 0, 0, NULL };
#ifdef RECORD_LESS_INTERESTING
entries_t readable = { 0, 0, NULL };
entries_t executable = { 0, 0, NULL };
#endif

uid_t uid;
gid_t groups[NGROUPS_MAX];
int ngroups = NGROUPS_MAX;


void perror_str(const char *fmt, ...);
char *my_stpcpy(char *dst, const char *src);

int in_group(gid_t fgid);
int is_executable(struct stat *sb);
int is_setuid(struct stat *sb);
int is_setguid(struct stat *sb);
int is_writable(struct stat *sb);
int is_readable(struct stat *sb);

void obtain_user_info(const char *user);
void report_findings(const char *name, entries_t *pentries);
void record_access(entries_t *pentries, const char *path, struct stat *sb);
void record_access_level(const char *path, struct stat *sb);
void scan_directory(const char *dir);


int
main(int c, char *v[])
{
    char canonical_path[PATH_MAX+1] = { 0 };
    int i, opt;
    char *user = NULL;

    /* process arguments */
    while ((opt = getopt(c, v, "u:")) != -1) {
        switch (opt) {
            case 'u':
                user = optarg;
                break;

            default:
                fprintf(stderr, "[!] Invalid option: -%c\n", opt);
                return 1;
        }
    }

    c -= optind;
    v += optind;

    /* get user info */
    obtain_user_info(user);

    /* process remaining args as directories */
    for (i = 0; i < c; i++) {
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
obtain_user_info(const char *user)
{
    struct passwd *pw;
    int i;

    if (!user)
        pw = getpwuid(getuid());
    else
        pw = getpwnam(user);
    if (!pw) {
        fprintf(stderr, "[!] Unable to find the user!\n");
        exit(1);
    }

    uid = pw->pw_uid;

    if (!user) {
        int num = getgroups(0, groups);
        if (num > ngroups) {
            fprintf(stderr, "[!] Too many groups!\n");
            exit(1);
        }
        if ((ngroups = getgroups(ngroups, groups)) == -1) {
            perror("[!] Unable to getgroups");
            exit(1);
        }

        /* make sure our gid is in the groups */
        if (!in_group(pw->pw_gid)) {
            if (ngroups == NGROUPS_MAX) {
                fprintf(stderr, "[!] Too many groups!!\n");
                exit(1);
            }
            groups[ngroups] = pw->pw_gid;
            ngroups++;
        }
    }
    else {
        /* since we are passing the max, we shouldn't have an issue with failed return */
        getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups);
    }

    /* print what we found :) */
    printf("[*] uid=(%u)%s, groups=", pw->pw_uid, pw->pw_name);
    for (i = 0; i < ngroups; i++) {
        struct group *pg = getgrgid(groups[i]);

        printf("%u(%s)", pg->gr_gid, pg->gr_name);
        if (i != ngroups - 1)
            printf(",");
    }
    printf("\n");
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
in_group(gid_t fgid)
{
    int i;

    for (i = 0; i < ngroups; i++) {
        if (groups[i] == fgid)
            return 1;
    }
    return 0;
}


int
is_executable(struct stat *sb)
{
    if (uid == 0)
        return 1;
    if (sb->st_mode & S_IXOTH)
        return 1;
    if ((sb->st_mode & S_IXUSR) && sb->st_uid == uid)
        return 1;
    if ((sb->st_mode & S_IXGRP) && in_group(sb->st_gid))
        return 1;
    return 0;
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
    /* although root can write to anything, it doesn't help us to show that here.
    if (uid == 0)
        return 1;
     */
    if (sb->st_mode & S_IWOTH)
        return 1;
    if ((sb->st_mode & S_IWUSR) && sb->st_uid == uid)
        return 1;
    if ((sb->st_mode & S_IWGRP) && in_group(sb->st_gid))
        return 1;
    return 0;
}


int
is_readable(struct stat *sb)
{
    /* although root can read from anything, it doesn't help us to show that here.
    if (uid == 0)
        return 1;
     */
    if (sb->st_mode & S_IROTH)
        return 1;
    if ((sb->st_mode & S_IRUSR) && sb->st_uid == uid)
        return 1;
    if ((sb->st_mode & S_IRGRP) && in_group(sb->st_gid))
        return 1;
    return 0;
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


char *my_stpcpy(char *dst, const char *src)
{
    char *q = dst;
    const char *p = src;

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

