if(_MSPAC_SUPPORT)
  include_directories(
    ${WBCLIENT_INCLUDE_DIR}
    )
endif(_MSPAC_SUPPORT)

if(USE_DBUS)
  include_directories(
    ${DBUS_INCLUDE_DIRS}
    )
endif(USE_DBUS)

########### next target ###############

SET(idmap_STAT_SRCS
   idmapper.c
   idmapper_cache.c
)

add_library(idmap STATIC ${idmap_STAT_SRCS})
add_sanitizers(idmap)

########### install files ###############
