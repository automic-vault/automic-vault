#ifndef ServiceManagementShim_h
#define ServiceManagementShim_h

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

char *AVBlessPrivilegedHelper(CFStringRef serviceName, AuthorizationRef authorization);

#endif
