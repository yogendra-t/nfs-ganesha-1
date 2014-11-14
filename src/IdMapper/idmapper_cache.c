/*
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * ---------------------------------------
 */

/**
 * \file    idmapper_cache.c
 * \author  $Author: deniel $
 * \date    $Date$
 * \version $Revision$
 * \brief   Id mapping functions
 *
 * idmapper_cache.c : Id mapping functions, passwd and groups cache management.
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _SOLARIS
#include "solaris_port.h"
#endif

#include "HashData.h"
#include "HashTable.h"
#include "log.h"
#include "nfs_core.h"
#include "nfs_exports.h"
#include "config_parsing.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

#ifdef _APPLE
#define strnlen( s, l ) strlen( s )
#else
size_t strnlen(const char *s, size_t maxlen);
#endif

/* Hashtable used to cache the hostname, accessed by their IP addess */
hash_table_t *ht_pwnam;
hash_table_t *ht_grnam;
hash_table_t *ht_pwuid;
hash_table_t *ht_grgid;
hash_table_t *ht_uidgid;

/**
 * @brief Overload mapping of uid/gid to buffdata values
 *
 * For uid->name map table, the key is uid and the value is (timestamp + name)
 * For name->uid map table, the key is name and the value is (timestamp + real_id)
 *
 * The idmap_val struct is allocated for each entry and added to hash table.
 * When the hash entry expires (after nfs_param.core_param.idmap_cache_timeout), 
 * the same idmap_val struct is reused when the entry is refreshed.
 */

struct idmap_val {
        time_t timestamp;
        union {
          uint32_t real_id;
          char *name;
        };
};

/**
 *
 * name_value_hash_func: computes the hash value for the entry in id mapper stuff
 *
 * Computes the hash value for the entry in id mapper stuff. In fact, it just use addresse as value (identity function) modulo the size of the hash.
 * This function is called internal in the HasTable_* function
 *
 * @param hparam [IN] hash table parameter.
 * @param buffcleff[in] pointer to the hash key buffer
 *
 * @return the computed hash value.
 *
 * @see HashTable_Init
 *
 */
uint32_t name_value_hash_func(hash_parameter_t * p_hparam,
                              hash_buffer_t    * buffclef)
{
  unsigned int sum = 0;
  unsigned int i = 0;
  unsigned char c;

  /* Compute the sum of all the characters */
  for(i = 0, c = ((char *)buffclef->pdata)[0]; ((char *)buffclef->pdata)[i] != '\0';
      c = ((char *)buffclef->pdata)[++i], sum += c) ;

  return (unsigned long)(sum % p_hparam->index_size);
}                               /*  ip_name_value_hash_func */


uint32_t id_value_hash_func(hash_parameter_t * p_hparam,
                            hash_buffer_t    * buffclef)
{
  return ((unsigned long)(buffclef->pdata) % p_hparam->index_size);
}

/**
 *
 * name_rbt_hash_func: computes the rbt value for the entry in the id mapper stuff.
 *
 * Computes the rbt value for the entry in the id mapper stuff.
 *
 * @param hparam [IN] hash table parameter.
 * @param buffcleff[in] pointer to the hash key buffer
 *
 * @return the computed rbt value.
 *
 * @see HashTable_Init
 *
 */
uint64_t name_rbt_hash_func(hash_parameter_t * p_hparam,
                            hash_buffer_t    * buffclef)
{
  uint64_t sum = 0;
  unsigned int i = 0;
  unsigned char c;

  /* Compute the sum of all the characters */
  for(i = 0, c = ((char *)buffclef->pdata)[0]; ((char *)buffclef->pdata)[i] != '\0';
      c = ((char *)buffclef->pdata)[++i], sum += c) ;

  return sum;
}                               /* ip_name_rbt_hash_func */

uint64_t id_rbt_hash_func(hash_parameter_t * p_hparam,
                          hash_buffer_t    * buffclef)
{
  return (unsigned long)(buffclef->pdata);
}

/**
 *
 * compare_name: compares the values stored in the key buffers.
 *
 * Compares the values stored in the key buffers. This function is to be used as 'compare_key' field in
 * the hashtable storing the nfs duplicated requests.
 *
 * @param buff1 [IN] first key
 * @param buff2 [IN] second key
 *
 * @return 0 if keys are identifical, 1 if they are different.
 *
 */
int compare_name(hash_buffer_t * buff1, hash_buffer_t * buff2)
{
  return strcmp((char *)(buff1->pdata), (char *)(buff2->pdata));
}                               /* compare_xid */

int compare_id(hash_buffer_t * buff1, hash_buffer_t * buff2)
{
  unsigned long xid1 = (unsigned long)(buff1->pdata);
  unsigned long xid2 = (unsigned long)(buff2->pdata);

  return (xid1 == xid2) ? 0 : 1;
}                               /* compare_xid */

/**
 *
 * display_idmapper_name: displays the name stored in the buffer.
 *
 * Displays the name stored in the buffer.
 *
 * @param buff1 [IN]  buffer to display
 * @param buff2 [OUT] output string
 *
 * @return number of character written.
 *
 */
int display_idmapper_name(struct display_buffer * dspbuf, hash_buffer_t * pbuff)
{
  struct idmap_val *val = pbuff->pdata;
  return display_cat(dspbuf, val->name);
}                               /* display_idmapper */

/**
 *
 * display_idmapper_id: displays the id stored in the buffer.
 *
 * Displays the id stored in the buffer.
 *
 * @param buff1 [IN]  buffer to display
 * @param buff2 [OUT] output string
 *
 * @return number of character written.
 *
 */
int display_idmapper_id(struct display_buffer * dspbuf, hash_buffer_t * pbuff)
{
  struct idmap_val *val = pbuff->pdata;
  return display_printf(dspbuf, "%u", val->real_id);
}                               /* display_idmapper_val */

void idmapper_init()
{
  LogDebug(COMPONENT_INIT, "Now building ID_MAPPER cache");

  if((ht_pwnam = HashTable_Init(&nfs_param.uidmap_cache_param.hash_param)) == NULL)
      LogFatal(COMPONENT_IDMAPPER,
               "NFS ID MAPPER: Cannot init IDMAP_UID cache");

  if((ht_pwuid = HashTable_Init(&nfs_param.unamemap_cache_param.hash_param)) == NULL)
      LogFatal(COMPONENT_IDMAPPER,
               "NFS ID MAPPER: Cannot init IDMAP_UNAME cache");

  if((ht_uidgid = HashTable_Init(&nfs_param.uidgidmap_cache_param.hash_param)) == NULL)
      LogFatal(COMPONENT_IDMAPPER,
               "NFS UID/GID MAPPER: Cannot init UIDGID_MAP cache");

  if((ht_grnam = HashTable_Init(&nfs_param.gidmap_cache_param.hash_param)) == NULL)
      LogFatal(COMPONENT_IDMAPPER,
               "NFS ID MAPPER: Cannot init IDMAP_GID cache");

  if((ht_grgid = HashTable_Init(&nfs_param.gnamemap_cache_param.hash_param)) == NULL)
      LogFatal(COMPONENT_IDMAPPER,
               "NFS ID MAPPER: Cannot init IDMAP_GNAME cache");

  LogInfo(COMPONENT_INIT,
          "ID_MAPPER cache successfully initialized");
}

/**
 *
 * idmap_add: Adds a value by key
 *
 * Adss a value by key.
 *
 * @param ht       [INOUT] the hash table to be used
 * @param key      [IN]  the ip address requested
 * @param val      [OUT] the value
 * @param overwrite [IN] Overwrite exising value if present
 *
 * @return ID_MAPPER_SUCCESS, ID_MAPPER_INSERT_MALLOC_ERROR, ID_MAPPER_INVALID_ARGUMENT
 *
 */
int idmap_add(hash_table_t * ht, char *key, uint32_t val, int overwrite)
{
  hash_buffer_t del_buffkey;
  hash_buffer_t buffkey;
  hash_buffer_t buffdata;
  int rc;
  int status = ID_MAPPER_SUCCESS;
  struct idmap_val *local_val = NULL;

  if(ht == NULL || key == NULL)
    return ID_MAPPER_INVALID_ARGUMENT;

  if(overwrite)
    {
      /* Remove the existing entry from hash table and reuse it.
         If the entry is not present then create new one 
      */
      del_buffkey.pdata = key;
      del_buffkey.len = strlen(key);
      if(HashTable_Get_and_Del(ht, &del_buffkey, &buffdata, &buffkey) == HASHTABLE_SUCCESS)
        {
          local_val = (struct idmap_val *)buffdata.pdata;
          local_val->real_id = val;
          local_val->timestamp = time(NULL);
          goto found;
        }
  }

  /* New insert. 
   * Create the buffkey and buffdata and build the key.
   */
  if((buffkey.pdata = gsh_strdup(key)) == NULL)
    {
      status = ID_MAPPER_INSERT_MALLOC_ERROR;
      goto err;
    }
  buffkey.len = strlen(key);

  /* Build the value */
  local_val = (struct idmap_val *)gsh_malloc(sizeof(struct idmap_val));
  if(local_val == NULL)
    {
      LogEvent(COMPONENT_IDMAPPER, "idmap_add: malloc failed");
      status = ID_MAPPER_INSERT_MALLOC_ERROR;
      goto err;
    }
  local_val->real_id = val;
  local_val->timestamp = time(NULL);

  buffdata.pdata = local_val;
  buffdata.len = sizeof(struct idmap_val);

found:
  LogFullDebug(COMPONENT_IDMAPPER, "Adding the following principal->uid mapping: %s->%lu",
               (char *)buffkey.pdata, (unsigned long int)local_val->real_id);

  rc = HashTable_Test_And_Set(ht, &buffkey, &buffdata,
                              HASHTABLE_SET_HOW_SET_NO_OVERWRITE);

  if(rc == HASHTABLE_ERROR_KEY_ALREADY_EXISTS)
    {
      /* Assume the insert operation as success
       * Still need to free up key and value
       */
      status = ID_MAPPER_SUCCESS;
      goto err;
    }

  if(rc != HASHTABLE_SUCCESS)
    {
      status = ID_MAPPER_INSERT_MALLOC_ERROR;
      goto err;
    }
  return ID_MAPPER_SUCCESS;

err:
  if(buffkey.pdata) gsh_free(buffkey.pdata);
  if(local_val) gsh_free(local_val);
  return status;
}                               /* idmap_add */

int namemap_add(hash_table_t * ht, uint32_t key, char *val, int overwrite)
{
  hash_buffer_t del_buffkey;
  hash_buffer_t buffkey;
  hash_buffer_t buffdata;
  int rc = 0;
  int status = ID_MAPPER_SUCCESS;
  struct idmap_val *local_val = NULL;

  if(ht == NULL || val == NULL)
    return ID_MAPPER_INVALID_ARGUMENT;

  if(overwrite)
    {
      /* Remove the existing entry from hash table and reuse it.
       * If the entry is not present then create new one 
       */
       del_buffkey.pdata = (void *)((unsigned long)key);
       del_buffkey.len = sizeof(void *);

       if(HashTable_Get_and_Del(ht, &del_buffkey, &buffdata, &buffkey) == HASHTABLE_SUCCESS)
         {
           local_val = (struct idmap_val *)buffdata.pdata;
           /* In comman case the mapping won't change.
            * In very rare case the uid to name mapping will change.
            * Compare the existing name to new name, if it is changed, then only malloc for new name.
            */
           if(strcmp(local_val->name, val))
             {
               /* Name has changed.*/
               gsh_free(local_val->name);
               if((local_val->name = gsh_strdup(val)) == NULL)
                 {
                   status = ID_MAPPER_INSERT_MALLOC_ERROR;
                   goto err;
                 }
             }
             local_val->timestamp = time(NULL);
             goto found;
        }
     }

  local_val = (struct idmap_val *)gsh_malloc(sizeof(struct idmap_val));
  if(local_val == NULL)
    {
      LogEvent(COMPONENT_IDMAPPER, "idmap_add: malloc failed");
      status = ID_MAPPER_INSERT_MALLOC_ERROR;
      goto err;
    }
  if((local_val->name = gsh_strdup(val)) == NULL)
    {
      status = ID_MAPPER_INSERT_MALLOC_ERROR;
      goto err;
    }
  local_val->timestamp = time(NULL);

  /* Build the data */
  buffdata.pdata = (void *)local_val;
  buffdata.len = strlen(val) + sizeof(struct idmap_val);

  buffkey.pdata = (void *)((unsigned long)key);
  buffkey.len = sizeof(void *);

found:
  LogFullDebug(COMPONENT_IDMAPPER, "Adding the following uid->principal mapping: %lu->%s",
               (unsigned long int)buffkey.pdata, (char *)local_val->name);
  rc = HashTable_Test_And_Set(ht, &buffkey, &buffdata,
                              HASHTABLE_SET_HOW_SET_NO_OVERWRITE);

  if(rc == HASHTABLE_ERROR_KEY_ALREADY_EXISTS)
    {
      /* Assume the insert operation as success
       * Still need to free up key and value
       */
      status = ID_MAPPER_SUCCESS;
      goto err;
    }

  if(rc != HASHTABLE_SUCCESS)
  {
    status = ID_MAPPER_INSERT_MALLOC_ERROR;
    goto err;
  }
  return ID_MAPPER_SUCCESS;

err:
  if(local_val && local_val->name) gsh_free(local_val->name);
  if(local_val)gsh_free(local_val);
  return status;
}                               /* namemap_add */

int uidgidmap_add(uid_t key, gid_t value)
{
  hash_buffer_t buffkey;
  hash_buffer_t buffdata;
  int rc = 0;

  /* Build keys and data, no storage is used there, caddr_t pointers are just charged */
  buffkey.pdata = (void *)((unsigned long)key);
  buffkey.len = sizeof(void *);

  buffdata.pdata = (void *)((unsigned long)value);
  buffdata.len = sizeof(void *);

  rc = HashTable_Test_And_Set(ht_uidgid, &buffkey, &buffdata,
                              HASHTABLE_SET_HOW_SET_OVERWRITE);

  if(rc != HASHTABLE_SUCCESS && rc != HASHTABLE_ERROR_KEY_ALREADY_EXISTS)
    return ID_MAPPER_INSERT_MALLOC_ERROR;

  return ID_MAPPER_SUCCESS;
}                               /* uidgidmap_add */

static int uidgidmap_free(hash_buffer_t key, hash_buffer_t val)
{
  /* key and value are just an integers caste to ptr 
   * Nothing to free for key or value
   */
    LogFullDebug(COMPONENT_IDMAPPER, "Freeing uid->gid mapping: %lu->%lu",
		 (unsigned long)key.pdata, (unsigned long)val.pdata);
  return 1;
}

int uidgidmap_clear()
{
  int rc;
  LogInfo(COMPONENT_IDMAPPER, "Clearing all uid->gid map entries.");
  rc = HashTable_Delall(ht_uidgid, uidgidmap_free);
  if (rc != HASHTABLE_SUCCESS)
    return ID_MAPPER_FAIL;
  return ID_MAPPER_SUCCESS;
}

static int idmap_free(hash_buffer_t key, hash_buffer_t val)
{
  struct idmap_val *entry = (struct idmap_val *)val.pdata;
  if (entry != NULL)
    LogFullDebug(COMPONENT_IDMAPPER, "Freeing uid->name mapping: %lu->%s",
                 (unsigned long)key.pdata, entry->name);

  /* key is just an integer caste to ptr 
   * Nothing to free for key
   */

  /* Free up the value, which is of type idmap_val*/
  if(entry != NULL)
    { 
      gsh_free(entry->name);
      gsh_free(entry);
    }
  return 1;
}

int idmap_clear()
{
  int rc;
  LogInfo(COMPONENT_IDMAPPER, "Clearing all uid->name map entries.");
  rc = HashTable_Delall(ht_pwuid, idmap_free);
  if (rc != HASHTABLE_SUCCESS)
    return ID_MAPPER_FAIL;
  return ID_MAPPER_SUCCESS;
}

static int namemap_free(hash_buffer_t key, hash_buffer_t val)
{
  struct idmap_val *entry = (struct idmap_val *)val.pdata;
  if (entry != NULL)
    LogFullDebug(COMPONENT_IDMAPPER, "Freeing principal->uid mapping: %s->%lu",
                 (char *)key.pdata, (unsigned long)entry->real_id);


  /* key is charptr for name. Need to free it */
  if(key.pdata != NULL)
    gsh_free(key.pdata);

  /* val is of type idmap_val. Need to free it */
  if(entry != NULL)
    gsh_free(entry); 
  return 1;
}

int namemap_clear()
{
  int rc;
  LogInfo(COMPONENT_IDMAPPER, "Clearing all uid->principal map entries.");
  rc = HashTable_Delall(ht_pwnam, namemap_free);
  if (rc != HASHTABLE_SUCCESS)
    return ID_MAPPER_FAIL;
  return ID_MAPPER_SUCCESS;
}


int uidmap_add(char *key, uid_t val, int propagate, int overwrite)
{
  int rc1 = ID_MAPPER_SUCCESS;
  int rc2 = ID_MAPPER_SUCCESS;

  rc1 = idmap_add(ht_pwnam, key, val, overwrite);
  if(propagate)
    rc2 = namemap_add(ht_pwuid, val, key, overwrite);

  if(rc1 != ID_MAPPER_SUCCESS)
    return rc1;
  else if(rc2 != ID_MAPPER_SUCCESS)
    return rc2;

  return ID_MAPPER_SUCCESS;
}                               /* uidmap_add */

int unamemap_add(uid_t key, char *val, int propagate, int overwrite)
{
  int rc1 = ID_MAPPER_SUCCESS;
  int rc2 = ID_MAPPER_SUCCESS;

  rc1 = namemap_add(ht_pwuid, key, val, overwrite);
  if(propagate)
    rc2 = idmap_add(ht_pwnam, val, key, overwrite);

  if(rc1 != ID_MAPPER_SUCCESS)
    return rc1;
  else if(rc2 != ID_MAPPER_SUCCESS)
    return rc2;

  return ID_MAPPER_SUCCESS;
}                               /* unamemap_add */

int gidmap_add(char *key, gid_t val, int propagate, int overwrite)
{
  int rc1 = ID_MAPPER_SUCCESS;
  int rc2 = ID_MAPPER_SUCCESS;

  rc1 = idmap_add(ht_grnam, key, val, overwrite);
  if(propagate)
    rc2 = namemap_add(ht_grgid, val, key, overwrite);

  if(rc1 != ID_MAPPER_SUCCESS)
    return rc1;
  else if(rc2 != ID_MAPPER_SUCCESS)
    return rc2;

  return ID_MAPPER_SUCCESS;
}                               /* gidmap_add */

int gnamemap_add(gid_t key, char *val, int overwrite)
{
  int rc1 = 0;
  int rc2 = 0;

  rc1 = namemap_add(ht_grgid, key, val, overwrite);
  rc2 = idmap_add(ht_grnam, val, key, overwrite);

  if(rc1 != ID_MAPPER_SUCCESS)
    return rc1;
  else if(rc2 != ID_MAPPER_SUCCESS)
    return rc2;

  return ID_MAPPER_SUCCESS;
}                               /* gnamemap_add */

/**
 *
 * idmap_get: gets a value by key
 *
 * Gets a value by key.
 *
 * @param ht       [INOUT] the hash table to be used
 * @param key      [IN]  the ip address requested
 * @param pval     [OUT] the uid/gid.  Always uint32_t
 *
 * @return ID_MAPPER_SUCCESS or ID_MAPPER_NOT_FOUND or ID_MAPPER_CACHE_EXPIRE 
 *
 */
int idmap_get(hash_table_t * ht, char *key, uint32_t *pval)
{
  hash_buffer_t buffkey;
  hash_buffer_t buffval;
  int status;

  if(ht == NULL || key == NULL || pval == NULL)
    return ID_MAPPER_INVALID_ARGUMENT;

  buffkey.pdata = (caddr_t) key;
  buffkey.len = strlen(key);

  if(HashTable_Get(ht, &buffkey, &buffval) == HASHTABLE_SUCCESS)
    {
      struct idmap_val *entry = (struct idmap_val *) buffval.pdata;
      if(entry->timestamp > time(NULL) - (time_t)nfs_param.core_param.idmap_cache_timeout)
        {
          *pval = entry->real_id;
          status = ID_MAPPER_SUCCESS;
        }
      else
        {
          // Cache expired.
          LogFullDebug(COMPONENT_IDMAPPER, "Marking cache entry expired: %s->%lu",
                       key, (unsigned long)entry->real_id);
          status = ID_MAPPER_CACHE_EXPIRE;
        }
    }
  else
    {
      status = ID_MAPPER_NOT_FOUND;
    }

  return status;
}                               /* idmap_get */

int namemap_get(hash_table_t * ht, uint32_t key, char *pval, size_t size)
{
  hash_buffer_t buffkey;
  hash_buffer_t buffval;
  int status;

  if(ht == NULL || pval == NULL)
    return ID_MAPPER_INVALID_ARGUMENT;

  buffkey.pdata = (void *)((unsigned long)key);
  buffkey.len = sizeof(void *);

  if(HashTable_Get(ht, &buffkey, &buffval) == HASHTABLE_SUCCESS)
    {
      struct idmap_val *entry = (struct idmap_val *)buffval.pdata;
      if(entry->timestamp > time(NULL) - (time_t)nfs_param.core_param.idmap_cache_timeout)
        {
          strmaxcpy(pval, entry->name, size);
          status = ID_MAPPER_SUCCESS;
        }
      else
        {
          // Cache expired.
          LogFullDebug(COMPONENT_IDMAPPER, "Marking cache entry expired: %lu->%s",
                       (unsigned long)key, entry->name);
          status = ID_MAPPER_CACHE_EXPIRE;
        }
    }
  else
    {
      status = ID_MAPPER_NOT_FOUND;
    }

  return status;
}                               /* namemap_get */

int uidgidmap_get(uid_t key, gid_t *pval)
{
  hash_buffer_t buffkey;
  hash_buffer_t buffval;
  int status;

  if(pval == NULL)
    return ID_MAPPER_INVALID_ARGUMENT;

  buffkey.pdata = (void *)((unsigned long)key);
  buffkey.len = sizeof(void *);

  if(HashTable_Get(ht_uidgid, &buffkey, &buffval) == HASHTABLE_SUCCESS)
    {
      *pval = (unsigned long)buffval.pdata;
      status = ID_MAPPER_SUCCESS;
    }
  else
    {
      /* WIth RPCSEC_GSS, it may be possible that 0 is not mapped to root */
      if(key == 0)
        {
          *pval = 0;
          status = ID_MAPPER_SUCCESS;
        }
      else
        status = ID_MAPPER_NOT_FOUND;
    }

  return status;
}                               /* uidgidmap_get */

int uidmap_get(char *key, uid_t *pval)
{
  return idmap_get(ht_pwnam, key, pval);
}

int unamemap_get(uid_t key, char *val, size_t size)
{
  return namemap_get(ht_pwuid, key, val, size);
}

int gidmap_get(char *key, gid_t *pval)
{
  return idmap_get(ht_grnam, key, pval);
}

int gnamemap_get(gid_t key, char *val, size_t size)
{
  return namemap_get(ht_grgid, key, val, size);
}

/**
 *
 * idmap_remove: Tries to remove an entry for ID_MAPPER
 *
 * Tries to remove an entry for ID_MAPPER
 *
 * @param ht            [INOUT] the hash table to be used
 * @param key           [IN]    the key uncached.
 *
 * @return the delete status
 *
 */
int idmap_remove(hash_table_t * ht, char *key)
{
  hash_buffer_t buffkey, old_key;
  int status;

  if(ht == NULL || key == NULL)
    return ID_MAPPER_INVALID_ARGUMENT;

  buffkey.pdata = key;
  buffkey.len = strlen(key);

  if(HashTable_Del(ht, &buffkey, &old_key, NULL) == HASHTABLE_SUCCESS)
    {
      status = ID_MAPPER_SUCCESS;
      gsh_free(old_key.pdata);
    }
  else
    {
      status = ID_MAPPER_NOT_FOUND;
    }

  return status;
}                               /* idmap_remove */

int namemap_remove(hash_table_t * ht, uint32_t key)
{
  hash_buffer_t buffkey;
  int status;

  if(ht == NULL)
    return ID_MAPPER_INVALID_ARGUMENT;

  buffkey.pdata = (void *)((unsigned long)key);
  buffkey.len = sizeof(void *);

  if(HashTable_Del(ht, &buffkey, NULL, NULL) == HASHTABLE_SUCCESS)
    {
      status = ID_MAPPER_SUCCESS;
    }
  else
    {
      status = ID_MAPPER_NOT_FOUND;
    }

  return status;
}                               /* idmap_remove */

int uidgidmap_remove(uid_t key)
{
  hash_buffer_t buffkey;
  int status;

  buffkey.pdata = (void *)((unsigned long)key);
  buffkey.len = sizeof(void *);

  if(HashTable_Del(ht_uidgid, &buffkey, NULL, NULL) == HASHTABLE_SUCCESS)
    {
      status = ID_MAPPER_SUCCESS;
    }
  else
    {
      status = ID_MAPPER_NOT_FOUND;
    }

  return status;
}                               /* uidgidmap_remove */

int uidmap_remove(char *key)
{
  return idmap_remove(ht_pwnam, key);
}

int unamemap_remove(uid_t key)
{
  return namemap_remove(ht_pwuid, key);
}

int gidmap_remove(char *key)
{
  return idmap_remove(ht_grnam, key);
}

int gnamemap_remove(gid_t key)
{
  return namemap_remove(ht_grgid, key);
}

/**
 *
 * idmap_populate_by_conf: Use the configuration file to populate the ID_MAPPER.
 *
 * Use the configuration file to populate the ID_MAPPER.
 *
 *
 */
int idmap_populate(char *path, idmap_type_t maptype)
{
  config_file_t config_file;
  config_item_t block;
  int var_max;
  int var_index;
  int err;
  char *key_name;
  char *key_value;
  const char *label;
  hash_table_t *ht = NULL;
  hash_table_t *ht_reverse = NULL;
  int rc = 0;

  config_file = config_ParseFile(path);

  if(!config_file)
    {
      LogCrit(COMPONENT_IDMAPPER,
              "Can't open file %s", path);

      return ID_MAPPER_INVALID_ARGUMENT;
    }

  switch (maptype)
    {
    case UIDMAP_TYPE:
      label = CONF_LABEL_UID_MAPPER_TABLE;
      ht = ht_pwnam;
      ht_reverse = ht_pwuid;
      break;

    case GIDMAP_TYPE:
      label = CONF_LABEL_GID_MAPPER_TABLE;
      ht = ht_grnam;
      ht_reverse = ht_grgid;
      break;

    default:
      /* Using incoherent value */
      return ID_MAPPER_INVALID_ARGUMENT;
      break;
    }

  /* Get the config BLOCK */
  if((block = config_FindItemByName(config_file, label)) == NULL)
    {
      LogCrit(COMPONENT_IDMAPPER,
              "Can't get label %s in file %s", label, path);
      return ID_MAPPER_INVALID_ARGUMENT;
    }
  else if(config_ItemType(block) != CONFIG_ITEM_BLOCK)
    {
      /* Expected to be a block */
      LogCrit(COMPONENT_IDMAPPER,
              "Label %s in file %s is expected to be a block", label, path);
      return ID_MAPPER_INVALID_ARGUMENT;
    }

  var_max = config_GetNbItems(block);

  for(var_index = 0; var_index < var_max; var_index++)
    {
      config_item_t item;
      uint64_t value = 0;

      item = config_GetItemByIndex(block, var_index);

      /* Get key's name */
      if((err = config_GetKeyValue(item, &key_name, &key_value)) != 0)
        {
          LogCrit(COMPONENT_IDMAPPER,
                  "Error reading key[%d] from section \"%s\" of configuration file.",
                  var_index, label);
          return ID_MAPPER_INVALID_ARGUMENT;
        }
      errno = 0;
      value = strtoul(key_value, NULL, 10);
      if(errno != 0 || value > UINT_MAX)
          return ID_MAPPER_INVALID_ARGUMENT;

      if((rc = idmap_add(ht, key_name, (uint32_t)value, 0)) != ID_MAPPER_SUCCESS)
        return rc;

      if((rc = namemap_add(ht_reverse, (uint32_t)value, key_name, 0)) != ID_MAPPER_SUCCESS)
        return rc;

    }

  /* HashTable_Log( ht ) ; */
  /* HashTable_Log( ht_reverse ) ; */

  return ID_MAPPER_SUCCESS;
}                               /* idmap_populate_by_conf */

/**
 *
 * idmap_get_stats: gets the hash table statistics for the idmap et the reverse id map
 *
 * Gets the hash table statistics for the idmap et the reverse idmap.
 *
 * @param maptype [IN] type of the mapping to be queried (should be UIDMAP_TYPE or GIDMAP_TYPE)
 * @param phstat [OUT] pointer to the resulting stats for direct map.
 * @param phstat [OUT] pointer to the resulting stats for reverse map.
 *
 * @return nothing (void function)
 *
 * @see HashTable_GetStats
 *
 */
void idmap_get_stats(idmap_type_t maptype, hash_stat_t * phstat,
                     hash_stat_t * phstat_reverse)
{
  hash_table_t *ht = NULL;
  hash_table_t *ht_reverse = NULL;

  switch (maptype)
    {
    case UIDMAP_TYPE:
      ht = ht_pwnam;
      ht_reverse = ht_pwuid;
      break;

    case GIDMAP_TYPE:
      ht = ht_grnam;
      ht_reverse = ht_grgid;
      break;

    default:
      /* Using incoherent value */
      return;
      break;
    }

  HashTable_GetStats(ht, phstat);
  HashTable_GetStats(ht_reverse, phstat_reverse);

}                               /* idmap_get_stats */
