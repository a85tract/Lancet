#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

#define lua_c
#include "lprefix.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static lua_State *globalL = NULL;

static void lstop(lua_State *L, lua_Debug *ar) {
    (void)ar;
    lua_sethook(L, NULL, 0, 0);
    luaL_error(L, "interrupted!");
}

static void laction(int i) {
    signal(i, SIG_DFL);
    lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE | LUA_MASKCOUNT, 1);
}

static int msghandler(lua_State *L) {
    const char *msg = lua_tostring(L, 1);
    if (msg == NULL) {
        if (luaL_callmeta(L, 1, "__tostring") && lua_type(L, -1) == LUA_TSTRING)
            return 1;
        else
            msg = lua_pushfstring(L, "(error object is a %s value)", luaL_typename(L, 1));
    }
    luaL_traceback(L, L, msg, 1);
    return 1;
}

static int docall(lua_State *L, int narg, int nres) {
    int base = lua_gettop(L) - narg;
    lua_pushcfunction(L, msghandler);
    lua_insert(L, base);
    globalL = L;
    signal(SIGINT, laction);
    int status = lua_pcall(L, narg, nres, base);
    signal(SIGINT, SIG_DFL);
    lua_remove(L, base);
    return status;
}

static int dochunk(lua_State *L, int status) {
    if (status == LUA_OK) status = docall(L, 0, 0);
    return status;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    lua_State *L = luaL_newstate();
    if (L == NULL) return 0;
    luaL_openlibs(L);
    dochunk(L, luaL_loadbufferx(L, (const char *)data, size, "fuzz", "t"));
    lua_close(L);
    return 0;
}
