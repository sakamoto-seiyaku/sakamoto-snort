/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Experimental Android VLIB-only runtime for the NFQUEUE POC.
 *
 * This intentionally keeps the original VPP process shape where useful:
 * VLIB main loop, unix CLI, plugin loader, and VLIB memory setup.  It avoids
 * linking libvnet.so so we can measure the lower bound when VPP is used only
 * as a packet-processing runtime.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <vppinfra/clib.h>
#include <vppinfra/cpu.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/unix.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/threads.h>
#include <vpp/app/version.h>
#include <vlibmemory/memclnt.api_enum.h>

char *vlib_plugin_path = ".";
char *vlib_plugin_app_version = VPP_BUILD_VER;
char *vat_plugin_path = NULL;
char *vlib_default_runtime_dir = "vpp";

VLIB_NODE_FN (vpp_lite_error_drop_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);

  (void) node;
  vlib_buffer_free (vm, from, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (vpp_lite_error_drop_node) = {
  .name = "error-drop",
  .flags = VLIB_NODE_FLAG_IS_DROP,
  .vector_size = sizeof (u32),
};

static void
print_help (const char *progname)
{
  fformat (
    stdout,
    "Usage: %s [options] [startup configuration]\n"
    "  -c, --config <file>         Read startup configuration from file\n"
    "  -i, --interactive           Run in interactive mode\n"
    "      --no-alloc-intercept    Disable memory alloc/free interception\n"
    "  -v, --version               Print version information and exit\n"
    "  -h, --help                  Show this help message and exit\n",
    progname);
}

static void
print_version (void)
{
  fformat (stdout, "vpp-lite v%s built by %s on %s at %s\n", VPP_BUILD_VER,
	   VPP_BUILD_USER, VPP_BUILD_HOST, VPP_BUILD_DATE);
}

int
main (int argc, char *argv[])
{
  int i;
  void vl_msg_api_set_first_available_msg_id (u16);
  clib_mem_init_ex_args_t mem_init_args = {
    .log2_page_sz = CLIB_MEM_PAGE_SZ_DEFAULT,
    .memory_size = (1ULL << 30),
    .alloc_free_intercept = 1,
  };
  clib_mem_page_sz_t default_log2_hugepage_sz = CLIB_MEM_PAGE_SZ_UNKNOWN;
  const size_t config_max_size = 1ULL << 18;
  unformat_input_t input, sub_input;
  u8 *s = 0, *v = 0, *config;
  u32 main_core = ~0;
  int cpu_translate = 0;
  cpu_set_t cpuset;
  void *main_heap;
  u32 cfg_len = 0;
  char *config_file = 0;
  int opt;
  int config_arg_index = 1;
  enum
  {
    OPT_NO_ALLOC_INTERCEPT = CHAR_MAX + 1,
  };

  const struct option long_options[] = {
    { "config", required_argument, 0, 'c' },
    { "version", no_argument, 0, 'v' },
    { "interactive", no_argument, 0, 'i' },
    { "no-alloc-intercept", no_argument, 0, OPT_NO_ALLOC_INTERCEPT },
    { "help", no_argument, 0, 'h' },
    {},
  };

  clib_mem_init (0, 1 << 20);

  opterr = 0;
  while ((opt = getopt_long (argc, argv, "c:ivh", long_options, 0)) != -1)
    {
      switch (opt)
	{
	case 'c':
	  config_file = optarg;
	  break;
	case 'i':
	  unix_main.flags |= UNIX_FLAG_INTERACTIVE;
	  break;
	case 'v':
	  print_version ();
	  return 0;
	case 'h':
	  print_help (argv[0]);
	  return 0;
	case '?':
	  if (optopt == 'c')
	    fprintf (stderr, "%s: option '-%c' requires an argument\n",
		     argv[0], optopt);
	  else if (optopt)
	    fprintf (stderr, "%s: unrecognized option '-%c'\n", argv[0],
		     optopt);
	  else if (optind > 0 && optind <= argc)
	    fprintf (stderr, "%s: unrecognized option '%s'\n", argv[0],
		     argv[optind - 1]);
	  else
	    fprintf (stderr, "%s: unrecognized option\n", argv[0]);
	  print_help (argv[0]);
	  return 1;
	case OPT_NO_ALLOC_INTERCEPT:
	  mem_init_args.alloc_free_intercept = 0;
	  break;
	default:
	  break;
	}
    }

  config = mmap (0, config_max_size, PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (config == MAP_FAILED)
    {
      fprintf (stderr, "Failed to allocate config buffer\n");
      return 1;
    }

  config_arg_index = optind;
  if (config_file)
    {
      int fd = open (config_file, O_RDONLY);
      ssize_t n_read;
      u8 buf[4096];
      int skip_line = 0;

      if (fd < 0)
	{
	  fprintf (stderr, "failed to open configuration file '%s'\n",
		   config_file);
	  munmap (config, config_max_size);
	  return 1;
	}

      while ((n_read = read (fd, buf, sizeof (buf))) > 0)
	{
	  for (u32 j = 0; j < n_read; j++)
	    {
	      u8 c = buf[j];

	      if (skip_line)
		{
		  if (c == '\n' || c == '\r')
		    {
		      skip_line = 0;
		      c = ' ';
		    }
		  else
		    continue;
		}
	      else if (c == '#')
		{
		  skip_line = 1;
		  continue;
		}

	      if (c == '\r' || c == '\n' || c == '\t')
		c = ' ';

	      if (c == ' ')
		{
		  if (cfg_len == 0 || config[cfg_len - 1] == ' ')
		    continue;
		}

	      if (cfg_len + 1 >= config_max_size)
		{
		  fprintf (stderr, "startup config file is too large\n");
		  close (fd);
		  munmap (config, config_max_size);
		  return 1;
		}

	      config[cfg_len++] = c;
	    }
	}

      close (fd);

      if (n_read < 0)
	{
	  fprintf (stderr, "failed to read startup config file '%s'\n",
		   config_file);
	  munmap (config, config_max_size);
	  return 1;
	}

      if (cfg_len && config[cfg_len - 1] == ' ')
	cfg_len--;
      config[cfg_len] = 0;
    }
  else
    {
      for (i = config_arg_index; i < argc; i++)
	cfg_len += sprintf ((char *) (config + cfg_len), "%s%s",
			    cfg_len ? " " : "", argv[i]);
      config[cfg_len] = 0;
    }

  unformat_init_string (&input, (const char *) config, (int) cfg_len);

  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "plugin_path %s", &vlib_plugin_path))
	;
      else if (unformat (&input, "test_plugin_path %s", &vat_plugin_path))
	;
      else if (unformat (&input, "memory %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  while (unformat_check_input (&sub_input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (&sub_input, "default-hugepage-size %U",
			    unformat_log2_page_size,
			    &default_log2_hugepage_sz))
		;
	      else if (unformat (&sub_input, "main-heap-size %U",
				 unformat_memory_size,
				 &mem_init_args.memory_size))
		;
	      else if (unformat (&sub_input, "main-heap-page-size %U",
				 unformat_log2_page_size,
				 &mem_init_args.log2_page_sz))
		;
	      else if (unformat (&sub_input, "%v", &v))
		vec_reset_length (v);
	    }
	  unformat_free (&sub_input);
	}
      else if (unformat (&input, "cpu %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  if (unformat (&sub_input, "main-core %u", &main_core))
	    ;
	  if (unformat (&sub_input, "relative"))
	    cpu_translate = 1;
	  else if (unformat (&sub_input, "%v", &v))
	    vec_reset_length (v);
	}
      else if (unformat (&input, "unix %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  while (unformat_check_input (&sub_input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (&sub_input, "interactive"))
		unix_main.flags |= UNIX_FLAG_INTERACTIVE;
	      if (unformat (&sub_input, "nosyslog"))
		unix_main.flags |= UNIX_FLAG_NOSYSLOG;
	      else if (unformat (&sub_input, "%v", &v))
		vec_reset_length (v);
	    }
	  unformat_free (&sub_input);
	}
      else if (!unformat (&input, "%s %v", &s, &v))
	break;

      vec_reset_length (s);
      vec_reset_length (v);
    }
  vec_free (s);
  vec_free (v);

  unformat_free (&input);

  int translate_main_core =
    os_translate_cpu_to_affinity_bitmap ((int) main_core);

  if (cpu_translate && main_core != ~0)
    {
      if (translate_main_core == -1)
	clib_error ("cpu %u is not available to be used"
		    " for the main thread in relative mode",
		    main_core);
      main_core = translate_main_core;
    }

  if (main_core == ~0)
    main_core = sched_getcpu ();

  if (main_core != ~0)
    {
      CPU_ZERO (&cpuset);
      CPU_SET (main_core, &cpuset);
      if (pthread_setaffinity_np (pthread_self (), sizeof (cpu_set_t),
				  &cpuset))
	{
	  clib_unix_error (
	    "pthread_setaffinity_np() on cpu %d failed for main thread",
	    main_core);
	}
    }

  clib_mem_destroy ();

  main_heap = clib_mem_init_ex (&mem_init_args);
  if (!main_heap)
    {
      fprintf (stderr, "main heap allocation failure: %s (%d)\n",
	       strerror (errno), errno);
      munmap (config, config_max_size);
      return 1;
    }

  vec_add (s, config, cfg_len);
  munmap (config, config_max_size);
  config = s;
  s = 0;

  __os_numa_index = clib_get_current_numa_node ();

  vl_msg_api_set_first_available_msg_id (VL_MSG_MEMCLNT_LAST + 1);

  if (default_log2_hugepage_sz != CLIB_MEM_PAGE_SZ_UNKNOWN)
    clib_mem_set_log2_default_hugepage_size (default_log2_hugepage_sz);

  vlib_main_init ();

  if (CLIB_DEBUG > 0)
    vlib_unix_cli_set_prompt ("DBGvpp-lite# ");
  else
    vlib_unix_cli_set_prompt ("vpp-lite# ");

  return vlib_unix_main (argc, argv, config);
}

static clib_error_t *
memory_config (vlib_main_t *vm, unformat_input_t *input)
{
  return 0;
}

static clib_error_t *
plugin_path_config (vlib_main_t *vm, unformat_input_t *input)
{
  return 0;
}

static clib_error_t *
test_plugin_path_config (vlib_main_t *vm, unformat_input_t *input)
{
  return 0;
}

VLIB_CONFIG_FUNCTION (memory_config, "memory");
VLIB_CONFIG_FUNCTION (plugin_path_config, "plugin_path");
VLIB_CONFIG_FUNCTION (test_plugin_path_config, "test_plugin_path");

void vl_msg_api_post_mortem_dump (void);
void vlib_post_mortem_dump (void);

void
os_panic (void)
{
  vl_msg_api_post_mortem_dump ();
  vlib_post_mortem_dump ();
  abort ();
}

void vhost_user_unmap_all (void) __attribute__ ((weak));
void
vhost_user_unmap_all (void)
{
}
