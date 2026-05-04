#ifndef IRON_PIPELINE_H
#define IRON_PIPELINE_H

int iron_pipeline_init(void);
void iron_pipeline_set_config(const char *conf_file);
void iron_pipeline_run_once(void);
void iron_pipeline_shutdown(void);

#endif /* IRON_PIPELINE_H */
