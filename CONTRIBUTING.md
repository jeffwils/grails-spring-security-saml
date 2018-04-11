# Contributing

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

We welcome contributions via both the raising of issues and submitting pull requests. But before you
do, please take a moment to consult the below.

## Submitting Issues

When you submit an issue, please take the time to provide as much info as you can. Key bits are:

1. What version of Grails
2. What version of the plugin
3. A concise description of your issue
4. More details of the issue, including any error logs etc.

Optionally, it's sometimes useful so know details about your IDP - what software or provider, etc.

## Submitting Code / Pull Requests

As per usual GitHub, please first fork the project and then branch off `develop` using a 'feature'
branch as per 'normal' [gitflow](http://nvie.com/posts/a-successful-git-branching-model/) practices.
E.g:

    git checkout -b feature/issue_123-short_description

Or better yet, use your gitflow tooling.

Please ensure you provide quality commit messages, and in the PR please details what testing you
have undertaken. Also, ideally provide some unit and/or integration tests as part of your PR.

### Gitflow Setup

To make it easier for new developers on the project a shell script is provided, simply run:

    ./gitflow-init.sh

Then if you wanted to be sure, you could run:

    git config -l --local

And make sure it has gitflow config settings.

However, if you want to do it manually with `git flow init` (or in your own tool), the following is
how your interaction should look.

<pre>
Which branch should be used for bringing forth production releases?
   - master
Branch name for production releases: [master]
Branch name for "next release" development: [develop]

How to name your supporting branch prefixes?
Feature branches? [feature/]
Bugfix branches? [bugfix/]
Release branches? [release/]
Hotfix branches? [hotfix/]
Support branches? [support/]
Version tag prefix? [] v
Hooks and filters directory? [/home/ian/projects/object-store/.git/hooks]
</pre>

Work on the majority of tickets should be on a feature branch, with a name of
`feature/<ticket>_<short-description>`. E.g. `/feature/1_first-feature`.

All work is initially merged into `develop` (so please select that for your PRs), and then once
we're ready for a new release a release branch will be created and the release finalised. After
that, the latest version will be available on `master` and tags will be in place.
