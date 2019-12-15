# User creation spoke
#
# Copyright (C) 2013-2014 Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# the GNU General Public License v.2, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY expressed or implied, including the implied warranties of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.  You should have received a copy of the
# GNU General Public License along with this program; if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.  Any Red Hat trademarks that are incorporated in the
# source code or documentation are not subject to the GNU General Public
# License and may only be used or replicated with the express permission of
# Red Hat, Inc.
#

import os
from pyanaconda.flags import flags
from pyanaconda.core.i18n import _, CN_
from pyanaconda.core.users import crypt_password, guess_username, check_groupname
from pyanaconda import input_checking
from pyanaconda.core import constants
from pyanaconda.modules.common.constants.services import USERS

from pyanaconda.ui.gui.spokes import NormalSpoke
from pyanaconda.ui.gui import GUIObject
from pyanaconda.ui.categories.user_settings import UserSettingsCategory
from pyanaconda.ui.helpers import InputCheck
from pyanaconda.ui.gui.helpers import GUISpokeInputCheckHandler, GUIDialogInputCheckHandler
from pyanaconda.ui.gui.utils import blockedHandler, set_password_visibility
from pyanaconda.ui.communication import hubQ
from pyanaconda.ui.lib.users import get_user_list, set_user_list

from pyanaconda.core.regexes import GROUPLIST_FANCY_PARSE

from pyanaconda.anaconda_loggers import get_module_logger
log = get_module_logger(__name__)

__all__ = ["UserSpoke"]


class UserSpoke(NormalSpoke, GUISpokeInputCheckHandler):
    """
       .. inheritance-diagram:: UserSpoke
          :parts: 3
    """
    builderObjects = ["userCreationWindow"]

    mainWidgetName = "userCreationWindow"
    focusWidgetName = "username_entry"
    uiFile = "spokes/user.glade"
    helpFile = "UserSpoke.xml"

    category = UserSettingsCategory

    icon = "avatar-default-symbolic"
    title = CN_("GUI|Spoke", "_User Creation")

    @classmethod
    def should_run(cls, environment, data):
        # the user spoke should run always in the anaconda and in firstboot only
        # when doing reconfig or if no user has been created in the installation

        users_module = USERS.get_proxy()
        user_list = get_user_list(users_module)

        if environment == constants.ANACONDA_ENVIRON:
            return True
        elif environment == constants.FIRSTBOOT_ENVIRON and data is None:
            # cannot decide, stay in the game and let another call with data
            # available (will come) decide
            return True
        elif environment == constants.FIRSTBOOT_ENVIRON and data and not user_list:
            return True
        else:
            return False

    def __init__(self, *args):
        NormalSpoke.__init__(self, *args)
        GUISpokeInputCheckHandler.__init__(self)

        self._users_module = USERS.get_proxy()

    def initialize(self):
        NormalSpoke.initialize(self)
        self.initialize_start()

        # We consider user creation requested if there was at least one user
        # in the DBus module user list at startup.
        # We also remember how the user was called so that we can clear it
        # in a reasonably safe way & if it was cleared.
        self._user_list = get_user_list(self._users_module, add_default=True)
        self._user_requested = False
        self._requested_user_cleared = False
        # if user has a name, it's an actual user that has been requested,
        # rather than a default user added by us
        if self.user.name:
            self._user_requested = True
            self._requested_user_name = self.user.name

        # gather references to relevant GUI objects

        # entry fields
        self._username_entry = self.builder.get_object("username_entry")
        self._password_entry = self.builder.get_object("password_entry")
        self._password_confirmation_entry = self.builder.get_object("password_confirmation_entry")
        # password checking status bar & label
        self._password_bar = self.builder.get_object("password_bar")
        self._password_label = self.builder.get_object("password_label")

        # Install the password checks:
        # - Has a password been specified?
        # - If a password has been specified and there is data in the confirm box, do they match?
        # - How strong is the password?
        # - Does the password contain non-ASCII characters?

        # Setup the password checker for password checking
        self._checker = input_checking.PasswordChecker(
                initial_password_content = self.password,
                initial_password_confirmation_content = self.password_confirmation,
                policy = input_checking.get_policy(self.data, "user")
        )
        # configure the checker for password checking
        self.checker.username = self.username
        self.checker.secret_type = constants.SecretType.PASSWORD
        # remove any placeholder texts if either password or confirmation field changes content from initial state
        self.checker.password.changed_from_initial_state.connect(self.remove_placeholder_texts)
        self.checker.password_confirmation.changed_from_initial_state.connect(self.remove_placeholder_texts)
        # connect UI updates to check results
        self.checker.checks_done.connect(self._checks_done)

        # username and full name checks
        self._username_check = input_checking.UsernameCheck()
        # empty username is considered a success so that the user can leave
        # the spoke without filling it in
        self._username_check.success_if_username_empty = True
        # check that the password is not empty
        self._empty_check = input_checking.PasswordEmptyCheck()
        # check that the content of the password field & the conformation field are the same
        self._confirm_check = input_checking.PasswordConfirmationCheck()
        # check password validity, quality and strength
        self._validity_check = input_checking.PasswordValidityCheck()
        # connect UI updates to validity check results
        self._validity_check.result.password_score_changed.connect(self.set_password_score)
        self._validity_check.result.status_text_changed.connect(self.set_password_status)
        # check if the password contains non-ascii characters
        self._ascii_check = input_checking.PasswordASCIICheck()

        # register the individual checks with the checker in proper order
        # 0) is the username and fullname valid ?
        # 1) is the password non-empty ?
        # 2) are both entered passwords the same ?
        # 3) is the password valid according to the current password checking policy ?
        # 4) is the password free of non-ASCII characters ?
        self.checker.add_check(self._username_check)
        self.checker.add_check(self._empty_check)
        self.checker.add_check(self._confirm_check)
        self.checker.add_check(self._validity_check)
        self.checker.add_check(self._ascii_check)

        self.guesser = {
            self.username_entry: True
            }

        # Configure levels for the password bar
        self.password_bar.add_offset_value("low", 2)
        self.password_bar.add_offset_value("medium", 3)
        self.password_bar.add_offset_value("high", 4)

        # Modify the GUI based on the kickstart and policy information
        # This needs to happen after the input checks have been created, since
        # the Gtk signal handlers use the input check variables.
        password_set_message = _("The password was set by kickstart.")
        if self.password_kickstarted:
            self.password_required = True
            self.password_entry.set_placeholder_text(password_set_message)
            self.password_confirmation_entry.set_placeholder_text(password_set_message)
        elif not self.checker.policy.emptyok:
            # Policy is that a non-empty password is required
            self.password_required = True

        # set the visibility of the password entries
        set_password_visibility(self.password_entry, False)
        set_password_visibility(self.password_confirmation_entry, False)

        # report that we are done
        self.initialize_done()

    @property
    def username_entry(self):
        return self._username_entry

    @property
    def username(self):
        return self.username_entry.get_text()

    @username.setter
    def username(self, new_username):
        self.username_entry.set_text(new_username)

    @property
    def user(self):
        """The user that is manipulated by the User spoke.

        This user is always the first one in the user list.

        :return: a UserData instance
        """
        return self._user_list[0]

    def refresh(self):
        # user data could have changed in the Users DBus module
        # since the last visit, so reload it from DBus
        #
        # In the case that the user list is empty or
        # a requested user has been cleared from the list in previous
        # spoke visit we need to have an empty user instance prepended
        # to the list.
        self._user_list = get_user_list(self._users_module, add_default=True, add_if_not_empty=self._requested_user_cleared)

        self.username = self.user.name

        # rerun checks so that we have a correct status message, if any
        self.checker.run_checks()

    @property
    def status(self):
        user_list = get_user_list(self._users_module)
        if not user_list:
            return _("No user will be created")
        elif user_list[0].has_admin_priviledges():
            return _("Administrator %s will be created") % user_list[0].name
        else:
            return _("User %s will be created") % user_list[0].name

    @property
    def mandatory(self):
        """Only mandatory if no admin user has been requested."""
        return True

    def apply(self):
        # set the password only if the user enters anything to the text entry
        # this should preserve the kickstart based password
        if self.password:
            self.password_kickstarted = False
            self.user.password = crypt_password(self.password)
            self.user.is_crypted = True
            self.remove_placeholder_texts()

        self.user.name = self.username

        if "wheel" not in self.user.groups:
            self.user.groups.append("wheel")
        if "qubes" not in self.user.groups:
            self.user.groups.append("qubes")

        # We make it possible to clear users requested from kickstart (or DBus API)
        # during an interactive installation. This is done by setting their name
        # to "". Then during apply() we will check the user name and if it is
        # equal to "", we will remember that locally and not forward the user which
        # has been cleared to the DBus module, by using the remove_uset flag
        # for the set_user_list function.

        # record if the requested user has been explicitely unset
        self._requested_user_cleared = not self.user.name
        # clear the unset user (if any)
        set_user_list(self._users_module, self._user_list, remove_unset=True)

    @property
    def sensitive(self):
        # Spoke cannot be entered if a user was set in the kickstart and the user
        # policy doesn't allow changes.
        return not (self.completed and flags.automatedInstall
                    and self._user_requested and not self.checker.policy.changesok)

    @property
    def completed(self):
        return bool(get_user_list(self._users_module))

    def on_password_icon_clicked(self, entry, icon_pos, event):
        """Called by Gtk callback when the icon of a password entry is clicked."""
        set_password_visibility(entry, not entry.get_visibility())

    def on_username_set_by_user(self, editable, data=None):
        """Called by Gtk on user-driven changes to the username field.

           This handler is blocked during changes from the username guesser.
        """

        # If the user set a user name, turn off the username guesser.
        # If the user cleared the username, turn it back on.
        if editable.get_text():
            self.guesser = False
        else:
            self.guesser = True

    def on_username_changed(self, editable, data=None):
        """Called by Gtk on all username changes."""
        new_username = editable.get_text()

        # update the username in checker
        self.checker.username = new_username

        # Skip the empty password checks if no username is set,
        # otherwise the user will not be able to leave the
        # spoke if password is not set but policy requires that.
        self._empty_check.skip = not new_username
        self._validity_check.skip = not new_username
        # Re-run the password checks against the new username
        self.checker.run_checks()

    def _checks_done(self, error_message):
        """Update the warning with the input validation error from the first
           error message or clear warnings if all the checks were successful.

           Also appends the "press twice" suffix if compatible with current
           password policy and handles the press-done-twice logic.
        """

        # check if an unwaivable check failed
        unwaivable_checks = [not self._confirm_check.result.success,
                             not self._username_check.result.success,
                             not self._empty_check.result.success]
        # with emptyok == False the empty password check become unwaivable
        #if not self.checker.policy.emptyok:
        #    unwaivable_checks.append(not self._empty_check.result.success)
        unwaivable_check_failed = any(unwaivable_checks)

        # set appropriate status bar message
        if not error_message:
            # all is fine, just clear the message
            self.clear_info()
        elif not self.username and not self.password and not self.password_confirmation:
            # Clear any info message if username and both the password and password
            # confirmation fields are empty.
            # This shortcut is done to make it possible for the user to leave the spoke
            # without inputting any username or password. Separate logic makes sure an
            # empty string is not unexpectedly set as the user password.
            self.clear_info()
        elif not self.username and not self.password and not self.password_confirmation:
            # Also clear warnings if username is set but empty password is fine.
            self.clear_info()
        else:
            if self.checker.policy.strict or unwaivable_check_failed:
                # just forward the error message
                self.show_warning_message(error_message)
            else:
                # add suffix for the click twice logic
                self.show_warning_message("{} {}".format(error_message,
                                                         _(constants.PASSWORD_DONE_TWICE)))

        # check if the spoke can be exited after the latest round of checks
        self._check_spoke_exit_conditions(unwaivable_check_failed)

    def _check_spoke_exit_conditions(self, unwaivable_check_failed):
        """Check if the user can escape from the root spoke or stay forever !"""

        # reset any waiving in progress
        self.waive_clicks = 0

        # Depending on the policy we allow users to waive the password strength
        # and non-ASCII checks. If the policy is set to strict, the password
        # needs to be strong, but can still contain non-ASCII characters.
        self.can_go_back = False
        self.needs_waiver = True

        # This shortcut is done to make it possible for the user to leave the spoke
        # without inputting anything. Separate logic makes sure an
        # empty string is not unexpectedly set as the user password.
        if not self.username and not self.password and not self.password_confirmation:
            self.can_go_back = True
            self.needs_waiver = False
        elif self.checker.success:
            # if all checks were successful we can always go back to the hub
            self.can_go_back = True
            self.needs_waiver = False
        elif unwaivable_check_failed:
            self.can_go_back = False
        elif not self.password and not self.password_confirmation:
            self.can_go_back = True
            self.needs_waiver = False
        else:
            if self.checker.policy.strict:
                if not self._validity_check.result.success:
                    # failing validity check in strict
                    # mode prevents us from going back
                    self.can_go_back = False
                elif not self._ascii_check.result.success:
                    # but the ASCII check can still be waived
                    self.can_go_back = True
                    self.needs_waiver = True
                else:
                    self.can_go_back = True
                    self.needs_waiver = False
            else:
                if not self._confirm_check.result.success:
                    self.can_go_back = False
                if not self._validity_check.result.success:
                    self.can_go_back = True
                    self.needs_waiver = True
                elif not self._ascii_check.result.success:
                    self.can_go_back = True
                    self.needs_waiver = True
                else:
                    self.can_go_back = True
                    self.needs_waiver = False

    def on_back_clicked(self, button):
        # the GUI spoke input check handler handles the spoke exit logic for us
        if self.try_to_go_back():
            NormalSpoke.on_back_clicked(self, button)
        else:
            log.info("Return to hub prevented by password checking rules.")
