#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static NSMutableDictionary *isotope_generic_password_query(NSString *service,
                                                           NSString *account) {
  NSMutableDictionary *query = [@{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: service,
    (__bridge id)kSecAttrAccount: account,
  } mutableCopy];

  SecKeychainRef defaultKeychain = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  OSStatus status = SecKeychainCopyDefault(&defaultKeychain);
#pragma clang diagnostic pop
  if (status == errSecSuccess && defaultKeychain != NULL) {
    query[(__bridge id)kSecUseKeychain] = CFBridgingRelease(defaultKeychain);
  }

  return query;
}

static NSMutableDictionary *
isotope_dotenv_private_key_query(NSString *service, NSString *account,
                                 NSString *accessGroup) {
  return [@{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: service,
    (__bridge id)kSecAttrAccount: account,
    (__bridge id)kSecUseDataProtectionKeychain: @YES,
    (__bridge id)kSecAttrAccessGroup: accessGroup,
  } mutableCopy];
}

static NSMutableDictionary *
isotope_legacy_generic_passwords_query(NSString *service) {
  NSMutableDictionary *query = [@{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: service,
  } mutableCopy];

  SecKeychainRef defaultKeychain = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  OSStatus status = SecKeychainCopyDefault(&defaultKeychain);
#pragma clang diagnostic pop
  if (status == errSecSuccess && defaultKeychain != NULL) {
    query[(__bridge id)kSecUseKeychain] = CFBridgingRelease(defaultKeychain);
  }

  return query;
}

static NSString *isotope_security_error_message(OSStatus status,
                                                NSString *fallbackPrefix) {
  NSString *message = (__bridge_transfer NSString *)
      SecCopyErrorMessageString(status, NULL);
  if (message != nil) {
    return message;
  }
  return [NSString stringWithFormat:@"%@ (%d)", fallbackPrefix, (int)status];
}

static bool isotope_add_trusted_application(NSMutableArray *trustedApplications,
                                            const char *path,
                                            char **error_cstr) {
  SecTrustedApplicationRef application = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  OSStatus status = SecTrustedApplicationCreateFromPath(path, &application);
#pragma clang diagnostic pop
  if (status != errSecSuccess) {
    if (error_cstr != NULL) {
      NSString *message =
          isotope_security_error_message(status, @"trusted application failed");
      if (path != NULL) {
        message = [NSString stringWithFormat:@"%@ for %s", message, path];
      }
      *error_cstr = strdup(message.UTF8String);
    }
    return false;
  }
  [trustedApplications addObject:CFBridgingRelease(application)];
  return true;
}

static bool isotope_create_password_access(NSString *service,
                                           SecAccessRef *accessRef,
                                           char **error_cstr) {
  NSMutableArray *trustedApplications = [NSMutableArray array];
  if (!isotope_add_trusted_application(trustedApplications, NULL, error_cstr)) {
    return false;
  }

  NSArray<NSString *> *injectionPaths = @[@"/usr/local/bin/av"];
  NSFileManager *fileManager = NSFileManager.defaultManager;
  for (NSString *path in injectionPaths) {
    if (![fileManager isExecutableFileAtPath:path]) {
      continue;
    }
    if (!isotope_add_trusted_application(trustedApplications,
                                         path.fileSystemRepresentation,
                                         error_cstr)) {
      return false;
    }
  }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  OSStatus status = SecAccessCreate((__bridge CFStringRef)service,
                                    (__bridge CFArrayRef)trustedApplications,
                                    accessRef);
#pragma clang diagnostic pop
  if (status != errSecSuccess) {
    if (error_cstr != NULL) {
      NSString *message =
          isotope_security_error_message(status, @"keychain access failed");
      *error_cstr = strdup(message.UTF8String);
    }
    return false;
  }

  return true;
}

char *isotope_copy_generic_password_json_with_status(const char *service_cstr,
                                                     const char *account_cstr,
                                                     char **error_cstr,
                                                     int *status_out);
bool isotope_generic_password_exists(const char *service_cstr,
                                     const char *account_cstr,
                                     char **error_cstr,
                                     int *status_out);
char *isotope_copy_dotenv_private_key_with_status(
    const char *service_cstr, const char *account_cstr,
    const char *access_group_cstr, char **error_cstr, int *status_out);
bool isotope_store_dotenv_private_key(const char *service_cstr,
                                      const char *account_cstr,
                                      const char *access_group_cstr,
                                      const char *value_cstr,
                                      char **error_cstr, int *status_out);
bool isotope_delete_dotenv_private_key_with_status(
    const char *service_cstr, const char *account_cstr,
    const char *access_group_cstr, char **error_cstr, int *status_out);
char *isotope_copy_legacy_dotenv_private_key_accounts_json_with_status(
    const char *service_cstr, char **error_cstr, int *status_out);
bool isotope_delete_legacy_generic_password_with_status(
    const char *service_cstr, const char *account_cstr, char **error_cstr,
    int *status_out);

char *isotope_copy_generic_password_json(const char *service_cstr,
                                         const char *account_cstr,
                                         char **error_cstr) {
  return isotope_copy_generic_password_json_with_status(service_cstr,
                                                        account_cstr,
                                                        error_cstr, NULL);
}

char *isotope_copy_generic_password_json_with_status(const char *service_cstr,
                                                     const char *account_cstr,
                                                     char **error_cstr,
                                                     int *status_out) {
  @autoreleasepool {
    if (error_cstr != NULL) {
      *error_cstr = NULL;
    }
    if (status_out != NULL) {
      *status_out = errSecSuccess;
    }

    if (service_cstr == NULL || account_cstr == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("invalid keychain lookup arguments");
      }
      return NULL;
    }

    NSString *service = [NSString stringWithUTF8String:service_cstr];
    NSString *account = [NSString stringWithUTF8String:account_cstr];
    if (service == nil || account == nil) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("keychain lookup arguments must be UTF-8");
      }
      return NULL;
    }

    NSMutableDictionary *query = isotope_generic_password_query(service, account);
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status_out != NULL) {
      *status_out = (int)status;
    }
    if (status != errSecSuccess) {
      if (error_cstr != NULL) {
        NSString *message = (__bridge_transfer NSString *)
            SecCopyErrorMessageString(status, NULL);
        if (message == nil) {
          message = [NSString stringWithFormat:@"keychain lookup failed (%d)",
                                                (int)status];
        }
        *error_cstr = strdup(message.UTF8String);
      }
      return NULL;
    }

    NSData *data = CFBridgingRelease(result);
    if (data == nil) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("keychain lookup did not return data");
      }
      return NULL;
    }

    char *copy = calloc(data.length + 1, sizeof(char));
    if (copy == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("failed to allocate keychain buffer");
      }
      return NULL;
    }
    memcpy(copy, data.bytes, data.length);
    copy[data.length] = '\0';
    return copy;
  }
}

bool isotope_generic_password_exists(const char *service_cstr,
                                     const char *account_cstr,
                                     char **error_cstr,
                                     int *status_out) {
  @autoreleasepool {
    if (error_cstr != NULL) {
      *error_cstr = NULL;
    }
    if (status_out != NULL) {
      *status_out = errSecSuccess;
    }

    if (service_cstr == NULL || account_cstr == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("invalid keychain lookup arguments");
      }
      return false;
    }

    NSString *service = [NSString stringWithUTF8String:service_cstr];
    NSString *account = [NSString stringWithUTF8String:account_cstr];
    if (service == nil || account == nil) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("keychain lookup arguments must be UTF-8");
      }
      return false;
    }

    NSMutableDictionary *query = isotope_generic_password_query(service, account);
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
    if (status_out != NULL) {
      *status_out = (int)status;
    }
    if (status == errSecSuccess) {
      return true;
    }

    if (error_cstr != NULL) {
      NSString *message = (__bridge_transfer NSString *)
          SecCopyErrorMessageString(status, NULL);
      if (message == nil) {
        message = [NSString stringWithFormat:@"keychain lookup failed (%d)",
                                              (int)status];
      }
      *error_cstr = strdup(message.UTF8String);
    }
    return false;
  }
}

char *isotope_copy_dotenv_private_key_with_status(
    const char *service_cstr, const char *account_cstr,
    const char *access_group_cstr, char **error_cstr, int *status_out) {
  @autoreleasepool {
    if (error_cstr != NULL) {
      *error_cstr = NULL;
    }
    if (status_out != NULL) {
      *status_out = errSecSuccess;
    }

    if (service_cstr == NULL || account_cstr == NULL ||
        access_group_cstr == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("invalid dotenv keychain lookup arguments");
      }
      return NULL;
    }

    NSString *service = [NSString stringWithUTF8String:service_cstr];
    NSString *account = [NSString stringWithUTF8String:account_cstr];
    NSString *accessGroup =
        [NSString stringWithUTF8String:access_group_cstr];
    if (service == nil || account == nil || accessGroup == nil) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("dotenv keychain lookup arguments must be UTF-8");
      }
      return NULL;
    }

    NSMutableDictionary *query =
        isotope_dotenv_private_key_query(service, account, accessGroup);
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef result = NULL;
    OSStatus status =
        SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status_out != NULL) {
      *status_out = (int)status;
    }
    if (status != errSecSuccess) {
      if (error_cstr != NULL) {
        NSString *message =
            isotope_security_error_message(status, @"dotenv keychain lookup failed");
        *error_cstr = strdup(message.UTF8String);
      }
      return NULL;
    }

    NSData *data = CFBridgingRelease(result);
    if (data == nil) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("dotenv keychain lookup did not return data");
      }
      return NULL;
    }

    char *copy = calloc(data.length + 1, sizeof(char));
    if (copy == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("failed to allocate dotenv keychain buffer");
      }
      return NULL;
    }
    memcpy(copy, data.bytes, data.length);
    copy[data.length] = '\0';
    return copy;
  }
}

bool isotope_store_dotenv_private_key(const char *service_cstr,
                                      const char *account_cstr,
                                      const char *access_group_cstr,
                                      const char *value_cstr,
                                      char **error_cstr, int *status_out) {
  @autoreleasepool {
    if (error_cstr != NULL) {
      *error_cstr = NULL;
    }
    if (status_out != NULL) {
      *status_out = errSecSuccess;
    }

    if (service_cstr == NULL || account_cstr == NULL ||
        access_group_cstr == NULL || value_cstr == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("invalid dotenv keychain write arguments");
      }
      return false;
    }

    NSString *service = [NSString stringWithUTF8String:service_cstr];
    NSString *account = [NSString stringWithUTF8String:account_cstr];
    NSString *accessGroup =
        [NSString stringWithUTF8String:access_group_cstr];
    NSString *value = [NSString stringWithUTF8String:value_cstr];
    if (service == nil || account == nil || accessGroup == nil ||
        value == nil) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("dotenv keychain write arguments must be UTF-8");
      }
      return false;
    }

    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *query =
        isotope_dotenv_private_key_query(service, account, accessGroup);
    NSDictionary *attributes = @{(__bridge id)kSecValueData: data};
    OSStatus status =
        SecItemUpdate((__bridge CFDictionaryRef)query,
                      (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
      NSMutableDictionary *createQuery = [query mutableCopy];
      createQuery[(__bridge id)kSecValueData] = data;
      status = SecItemAdd((__bridge CFDictionaryRef)createQuery, NULL);
    }

    if (status_out != NULL) {
      *status_out = (int)status;
    }
    if (status != errSecSuccess) {
      if (error_cstr != NULL) {
        NSString *message =
            isotope_security_error_message(status, @"dotenv keychain write failed");
        *error_cstr = strdup(message.UTF8String);
      }
      return false;
    }

    return true;
  }
}

bool isotope_delete_dotenv_private_key_with_status(
    const char *service_cstr, const char *account_cstr,
    const char *access_group_cstr, char **error_cstr, int *status_out) {
  @autoreleasepool {
    if (error_cstr != NULL) {
      *error_cstr = NULL;
    }
    if (status_out != NULL) {
      *status_out = errSecSuccess;
    }

    if (service_cstr == NULL || account_cstr == NULL ||
        access_group_cstr == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("invalid dotenv keychain delete arguments");
      }
      return false;
    }

    NSString *service = [NSString stringWithUTF8String:service_cstr];
    NSString *account = [NSString stringWithUTF8String:account_cstr];
    NSString *accessGroup =
        [NSString stringWithUTF8String:access_group_cstr];
    if (service == nil || account == nil || accessGroup == nil) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("dotenv keychain delete arguments must be UTF-8");
      }
      return false;
    }

    NSMutableDictionary *query =
        isotope_dotenv_private_key_query(service, account, accessGroup);
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status_out != NULL) {
      *status_out = (int)status;
    }
    if (status != errSecSuccess && status != errSecItemNotFound) {
      if (error_cstr != NULL) {
        NSString *message =
            isotope_security_error_message(status, @"dotenv keychain delete failed");
        *error_cstr = strdup(message.UTF8String);
      }
      return false;
    }
    return true;
  }
}

char *isotope_copy_legacy_dotenv_private_key_accounts_json_with_status(
    const char *service_cstr, char **error_cstr, int *status_out) {
  @autoreleasepool {
    if (error_cstr != NULL) {
      *error_cstr = NULL;
    }
    if (status_out != NULL) {
      *status_out = errSecSuccess;
    }

    if (service_cstr == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("invalid legacy dotenv keychain enumeration arguments");
      }
      return NULL;
    }

    NSString *service = [NSString stringWithUTF8String:service_cstr];
    if (service == nil) {
      if (error_cstr != NULL) {
        *error_cstr =
            strdup("legacy dotenv keychain enumeration arguments must be UTF-8");
      }
      return NULL;
    }

    NSMutableDictionary *query = isotope_legacy_generic_passwords_query(service);
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;

    CFTypeRef result = NULL;
    OSStatus status =
        SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) {
      status = errSecSuccess;
      result = CFRetain((__bridge CFTypeRef)@[]);
    }
    if (status_out != NULL) {
      *status_out = (int)status;
    }
    if (status != errSecSuccess) {
      if (error_cstr != NULL) {
        NSString *message = isotope_security_error_message(
            status, @"legacy dotenv keychain enumeration failed");
        *error_cstr = strdup(message.UTF8String);
      }
      return NULL;
    }

    id rawRecords = CFBridgingRelease(result);
    NSArray *records = [rawRecords isKindOfClass:NSArray.class]
                           ? rawRecords
                           : (rawRecords == nil ? @[] : @[ rawRecords ]);
    NSMutableArray<NSString *> *accounts = [NSMutableArray array];
    for (id record in records) {
      if (![record isKindOfClass:NSDictionary.class]) {
        continue;
      }
      id account = record[(__bridge id)kSecAttrAccount];
      if ([account isKindOfClass:NSString.class]) {
        [accounts addObject:account];
      }
    }

    NSError *jsonError = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:accounts
                                                   options:0
                                                     error:&jsonError];
    if (json == nil) {
      if (error_cstr != NULL) {
        NSString *message = jsonError.localizedDescription ?:
            @"failed to encode legacy dotenv keychain account list";
        *error_cstr = strdup(message.UTF8String);
      }
      return NULL;
    }
    NSString *jsonString =
        [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    if (jsonString == nil) {
      if (error_cstr != NULL) {
        *error_cstr =
            strdup("legacy dotenv keychain account list was not UTF-8");
      }
      return NULL;
    }
    return strdup(jsonString.UTF8String);
  }
}

bool isotope_delete_legacy_generic_password_with_status(
    const char *service_cstr, const char *account_cstr, char **error_cstr,
    int *status_out) {
  @autoreleasepool {
    if (error_cstr != NULL) {
      *error_cstr = NULL;
    }
    if (status_out != NULL) {
      *status_out = errSecSuccess;
    }

    if (service_cstr == NULL || account_cstr == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("invalid legacy keychain delete arguments");
      }
      return false;
    }

    NSString *service = [NSString stringWithUTF8String:service_cstr];
    NSString *account = [NSString stringWithUTF8String:account_cstr];
    if (service == nil || account == nil) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("legacy keychain delete arguments must be UTF-8");
      }
      return false;
    }

    NSMutableDictionary *query = isotope_generic_password_query(service, account);
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status_out != NULL) {
      *status_out = (int)status;
    }
    if (status != errSecSuccess && status != errSecItemNotFound) {
      if (error_cstr != NULL) {
        NSString *message =
            isotope_security_error_message(status, @"legacy keychain delete failed");
        *error_cstr = strdup(message.UTF8String);
      }
      return false;
    }
    return true;
  }
}

void isotope_free_c_string(char *value) {
  if (value != NULL) {
    free(value);
  }
}

bool isotope_post_distributed_notification_with_object(const char *name_cstr,
                                                       const char *object_cstr,
                                                       char **error_cstr);

bool isotope_post_distributed_notification(const char *name_cstr,
                                           char **error_cstr) {
  return isotope_post_distributed_notification_with_object(name_cstr, NULL,
                                                          error_cstr);
}

bool isotope_post_distributed_notification_with_object(const char *name_cstr,
                                                       const char *object_cstr,
                                                       char **error_cstr) {
  @autoreleasepool {
    if (error_cstr != NULL) {
      *error_cstr = NULL;
    }

    if (name_cstr == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("invalid distributed notification name");
      }
      return false;
    }

    NSString *name = [NSString stringWithUTF8String:name_cstr];
    if (name.length == 0) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("distributed notification name must be UTF-8");
      }
      return false;
    }

    NSString *object = nil;
    if (object_cstr != NULL) {
      object = [NSString stringWithUTF8String:object_cstr];
      if (object.length == 0) {
        if (error_cstr != NULL) {
          *error_cstr = strdup("distributed notification object must be UTF-8");
        }
        return false;
      }
    }

    [[NSDistributedNotificationCenter defaultCenter]
        postNotificationName:name
                      object:object
                    userInfo:nil
          deliverImmediately:YES];
    return true;
  }
}

bool isotope_store_generic_password_json(const char *service_cstr,
                                         const char *account_cstr,
                                         const char *value_cstr,
                                         char **error_cstr) {
  @autoreleasepool {
    if (error_cstr != NULL) {
      *error_cstr = NULL;
    }

    if (service_cstr == NULL || account_cstr == NULL || value_cstr == NULL) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("invalid keychain write arguments");
      }
      return false;
    }

    NSString *service = [NSString stringWithUTF8String:service_cstr];
    NSString *account = [NSString stringWithUTF8String:account_cstr];
    NSString *value = [NSString stringWithUTF8String:value_cstr];
    if (service == nil || account == nil || value == nil) {
      if (error_cstr != NULL) {
        *error_cstr = strdup("keychain write arguments must be UTF-8");
      }
      return false;
    }

    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *query = isotope_generic_password_query(service, account);

    // Changing access on an existing item can trigger a keychain authorization
    // dialog, so only attach our trusted-app ACL when creating a new item.
    NSDictionary *attributes = @{(__bridge id)kSecValueData: data};
    OSStatus status =
        SecItemUpdate((__bridge CFDictionaryRef)query,
                      (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
      SecAccessRef access = NULL;
      if (!isotope_create_password_access(service, &access, error_cstr)) {
        return false;
      }
      id accessObject = CFBridgingRelease(access);
      NSMutableDictionary *createQuery = [query mutableCopy];
      createQuery[(__bridge id)kSecValueData] = data;
      createQuery[(__bridge id)kSecAttrAccess] = accessObject;
      status = SecItemAdd((__bridge CFDictionaryRef)createQuery, NULL);
    }

    if (status != errSecSuccess) {
      if (error_cstr != NULL) {
        NSString *message =
            isotope_security_error_message(status, @"keychain write failed");
        *error_cstr = strdup(message.UTF8String);
      }
      return false;
    }

    return true;
  }
}
