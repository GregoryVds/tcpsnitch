#ifndef LOGGER_H
#define LOGGER_H

typedef enum LogLevel { INFO, WARN, ERROR } LogLevel;

void logger(LogLevel lvl, const char *formated_str, const char *file, int line);

#define LOG(lvl, format, args...)                                          \
	{                                                                  \
		char formated_string[1024];                                \
		snprintf(formated_string, sizeof(formated_string), format, \
			 ##args);                                          \
		logger(lvl, formated_string, __FILE__, __LINE__);          \
	}

#endif
