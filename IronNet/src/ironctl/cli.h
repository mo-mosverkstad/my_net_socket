#ifndef IRON_CLI_H
#define IRON_CLI_H

/* Start the CLI thread (reads stdin, executes commands) */
int cli_start(void);

/* Stop the CLI thread */
void cli_stop(void);

/* Process a single command line (also used for testing) */
int cli_execute(const char *line);

#endif /* IRON_CLI_H */
