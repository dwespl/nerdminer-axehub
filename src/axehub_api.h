#ifndef AXEHUB_API_H
#define AXEHUB_API_H

#ifdef AXEHUB_API_ENABLED

void axehub_api_start();

#else

inline void axehub_api_start() {}

#endif

#endif
