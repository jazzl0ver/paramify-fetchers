"""Key-routing mixins shared by the pages and the modals.

Textual's built-in widgets navigate vertically but never horizontally: Button
binds only `enter`, so a Yes/No row reads as a left-right choice and answers to
neither arrow. And Input leaves up/down unbound, so a filter box above a list
swallows the keys you would use to walk the results it just filtered.

Both mixins put their actions on the *container* (page or modal) rather than on
the widgets, which is what makes them safe: a key event bubbles up from the
focused widget, so anything that already owns the key keeps it. An Input's
left/right still moves its cursor; a Tree's up/down still moves its cursor. Only
the cases the built-ins leave unhandled ever reach these actions.

Textual merges BINDINGS along the DOMNode MRO only — a plain mixin's are not
picked up — so each class spreads the matching *_BINDINGS list into its own:

    class ConfirmModal(ButtonRowNav, ModalScreen[bool]):
        BINDINGS = [Binding("escape", "no", "No"), *BUTTON_ROW_BINDINGS]
"""

from __future__ import annotations

from textual.binding import Binding
from textual.widgets import Button

BUTTON_ROW_BINDINGS = [
    Binding("left", "button_prev", "Previous", show=False),
    Binding("right", "button_next", "Next", show=False),
]

FILTER_NAV_BINDINGS = [
    Binding("up", "filter_nav_up", "Up", show=False),
    Binding("down", "filter_nav_down", "Down", show=False),
]


class ButtonRowNav:
    """Left/right move focus along the row of buttons that holds the focused one.

    Scoped to the focused button's own parent, so a page with several action rows
    keeps each row a separate left-right group. Disabled buttons are skipped —
    they cannot take focus, and stepping onto one would strand the user.
    """

    def _step_button(self, delta: int) -> None:
        focused = self.app.focused
        if not isinstance(focused, Button) or focused.parent is None:
            return
        row = [
            child
            for child in focused.parent.children
            if isinstance(child, Button) and not child.disabled
        ]
        # A lone button has nowhere to go; wrap so the two-button dialogs (the
        # common case) answer to either arrow from either end.
        if focused not in row or len(row) < 2:
            return
        row[(row.index(focused) + delta) % len(row)].focus()

    def action_button_prev(self) -> None:
        self._step_button(-1)

    def action_button_next(self) -> None:
        self._step_button(1)


class FilterListNav:
    """Up/down typed into a filter box drive the list below it, without leaving
    the box — so you can keep narrowing the filter while you move the cursor.

    Set FILTER_NAV to (filter selector, list selector). The list only needs
    Textual's cursor actions, which both OptionList and Tree provide.
    """

    FILTER_NAV: tuple[str, str] = ("", "")

    def _filter_nav(self, down: bool) -> None:
        field_sel, list_sel = self.FILTER_NAV
        if not field_sel:
            return
        # Only act while the filter itself holds focus: once focus is in the
        # list, the list's own up/down bindings have already claimed the key.
        if not self.query_one(field_sel).has_focus:
            return
        target = self.query_one(list_sel)
        target.action_cursor_down() if down else target.action_cursor_up()

    def action_filter_nav_up(self) -> None:
        self._filter_nav(down=False)

    def action_filter_nav_down(self) -> None:
        self._filter_nav(down=True)
