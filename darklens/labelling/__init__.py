"""Tools for building a real, human-labelled evaluation set, so accuracy can be measured on real text.

Workflow (see docs/labelling.md):
  pool    gather public text (security news, tech headlines) and pick a spread that covers every class
  sheets  write one private CSV per labeller; everyone labels the same shared items, the rest are split up
  check   validate the filled-in sheets and measure how much the labellers agree with each other
  split   merge into one labelled set and split it into a tuning half and an untouched test half

The files it writes live in `labelling/` (git-ignored) because they hold third-party text that must not be
re-published. The model's guesses are never shown to labellers.
"""
