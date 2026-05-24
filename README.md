# proxy

A simple system for hooking protected applications.
I have employed this method to make hooks for various
MMORPG games, for the past two years.

```C
void __security_init_cookie(void);	// dear friend!
```

## Details

Most Windows binaries have a predictable pattern that can be used to our advantage.

To do this we take advantage of the fact that **`__security_init_cookie`** is called by the CRT when it's initialized.
The initialization is the first call at the OEP:

```
__int64 start()
{
  __security_init_cookie();	// hello!
  return __scrt_common_main_seh();
}
```

**GetSystemTimeAsFileTime** is the first import called first in **`__security_init_cookie`**

GetSystemTimeAsFileTime is embarassingly easily to recreate within our own code.
We only need only a few structures. And I do not wish to share my ntdll.h =x

We recreate the original GetSystemTimeAsFileTime function, and perform our hooking inside,
having added a check to determine when our target is decrypted in memory, and unhooking our hook
as our last step, not to add lag to the game.

**CLIENT_ID**
**KSYSTEM_TIME**
**KUSER_SHARED_DATA** (however we only need the first 5 entries of this structure)

For further elaboration on this idea, I suggest you look over the project code,
which I have made compatible with Windows 11 22H2, ...

In hopes someone finds purpose with it,

-Fyyre
