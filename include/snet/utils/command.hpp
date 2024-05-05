#pragma once
#include <memory>

class Manager
{
    /**
      * Get a registered command
      */
      static std::unique_ptr<Command> get_cmd(const std::string& name);

      static std::vector<std::string> registered_cmds();

};

class Command {
   public:
      

      /**
      * The spec string specifies the format of the command line, eg for
      * a somewhat complicated command:
      * cmd_name --flag --option1= --option2=opt2val input1 input2 *rest
      *
      * By default this is the value returned by help_text()
      *
      * The first value is always the command name. Options may appear
      * in any order. Named arguments are taken from the command line
      * in the order they appear in the spec.
      *
      * --flag can optionally be specified, and takes no value.
      * Check for it in go() with flag_set()
      *
      * --option1 is an option whose default value (if the option
      * does not appear on the command line) is the empty string.
      *
      * --option2 is an option whose default value is opt2val
      * Read the values in go() using get_arg or get_arg_sz.
      *
      * The values input1 and input2 specify named arguments which must
      * be provided. They are also access via get_arg/get_arg_sz
      * Because options and arguments for a single command share the same
      * namespace you can't have a spec like:
      *   cmd --input input
      * but you hopefully didn't want to do that anyway.
      *
      * The leading '*' on '*rest' specifies that all remaining arguments
      * should be packaged in a list which is available as get_arg_list("rest").
      * This can only appear on a single value and should be the final
      * named argument.
      *
      * Every command has implicit flags --help, --verbose and implicit
      * options --output= and --error-output= which override the default
      * use of std::cout and std::cerr.
      *
      * Use of --help is captured in run() and returns help_text().
      * Use of --verbose can be checked with verbose() or flag_set("verbose")
      */
      explicit Command(const std::string& cmd_spec);

      virtual ~Command();

      int run(const std::vector<std::string>& params);

      virtual std::string group() const = 0;

      virtual std::string description() const = 0;

      virtual std::string help_text() const;

      const std::string& cmd_spec() const { return m_spec; }

      std::string cmd_name() const;

   protected:
      /*
      * The actual functionality of the cli command implemented in subclass.
      * The return value from main will be zero.
      */
      virtual void go() = 0;

     

   private:
      typedef std::function<std::unique_ptr<Command>()> cmd_maker_fn;
      static std::map<std::string, cmd_maker_fn>& global_registry();

      void parse_spec();

      // set in constructor
      std::string m_spec;

      std::unique_ptr<Argument_Parser> m_args;
      std::unique_ptr<std::ostream> m_output_stream;
      std::unique_ptr<std::ostream> m_error_output_stream;

      std::shared_ptr<Botan::RandomNumberGenerator> m_rng;

      // possibly set by calling set_return_code()
      int m_return_code = 0;

   public:
      // the registry interface:

      class Registration final {
         public:
            Registration(const std::string& name, const cmd_maker_fn& maker_fn);
      };
};

#define REGISTER_COMMAND(name, CLI_Class)                \
   const Botan_CLI::Command::Registration reg_cmd_##CLI_Class( \
      name, []() -> std::unique_ptr<Botan_CLI::Command> { return std::make_unique<CLI_Class>(); })

}  // namespace Botan_CLI
