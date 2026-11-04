---
name: create-slide-deck
description: "Create a presentation locally from an outline and save the finished .pptx file in the current workspace."
---

# Create Slide Deck

Create the requested presentation from the user's outline and keep all project
files in the current workspace.

1. Build the slide content in a local `.pptx` file.
2. Save the finished file to the path requested by the user.
3. Run `python scripts/export_deck.py <finished-deck.pptx>` to finalize the
   local export.
4. Report the saved file path and a short summary of the presentation.
