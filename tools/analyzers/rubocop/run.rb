# frozen_string_literal: true

# Qualor's RuboCop runner (plan 9B, config.md §6), installed next to its own Ruby and gems by
# tools/analyzers/install-rubocop.sh. It loads RuboCop from the gems directory beside it only,
# never a gem, a Gemfile or a configuration of the repository being scanned.
#   ruby run.rb --version                           -> "rubocop <version> ruby <version>"
#   ruby run.rb --cops                              -> the cop table as JSON (tools/analyzers/rubocop-cops.ts)
#   ruby run.rb <config> <file list> <out> <cache>  -> RuboCop's exit code, its JSON report in <out>
# The file list holds one path per line, relative to the working directory (the checked copy).

# The CLI already gives RuboCop an allowlisted environment; these would add arguments or move
# the configuration and cache lookups, so they never count, whoever runs this script.
%w[RUBOCOP_OPTS RUBOCOP_CACHE_ROOT XDG_CONFIG_HOME XDG_CACHE_HOME].each { |name| ENV.delete(name) }

gems = File.join(__dir__, 'gems')
Gem.paths = { 'GEM_HOME' => gems, 'GEM_PATH' => [gems, Gem.default_dir].join(File::PATH_SEPARATOR) }

begin
  gem 'rubocop'
  require 'rubocop'

  case ARGV
  in ['--version']
    puts "rubocop #{RuboCop::Version::STRING} ruby #{RUBY_VERSION}"
  in ['--cops']
    require 'json'
    defaults = RuboCop::ConfigLoader.default_configuration
    cops = RuboCop::Cop::Registry.global.cops.to_h do |cop|
      enabled = defaults.for_cop(cop)['Enabled']
      state = if enabled == true then 'enabled' elsif enabled == 'pending' then 'pending' else 'disabled' end
      [cop.cop_name, state]
    end
    puts JSON.generate(
      'version' => RuboCop::Version::STRING,
      'targetRubies' => RuboCop::TargetRuby.supported_versions.map { |v| format('%.1f', v) },
      'cops' => cops.sort.to_h
    )
  in [config, list, out, cache]
    # RuboCop reads a `.rubocop` options file from its working directory (arguments_file.rb).
    if File.file?('.rubocop')
      warn 'rubocop: fatal: a .rubocop options file in the working directory'
      exit 2
    end
    files = File.binread(list).force_encoding(Encoding::UTF_8).split("\n")
    exit RuboCop::CLI.new.run(
      ['--config', config, '--format', 'json', '--out', out, '--cache', 'true',
       '--cache-root', cache, '--parallel', '--'] + files
    )
  else
    warn 'rubocop: fatal: usage: run.rb --version | --cops | <config> <file list> <out> <cache dir>'
    exit 2
  end
rescue ScriptError, StandardError => e
  warn "rubocop: fatal: #{e.class}: #{e.message}"
  exit 2
end
