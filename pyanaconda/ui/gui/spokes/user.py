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
import copy
from pyanaconda.flags import flags
from pyanaconda.core.i18n import _, CN_
from pyanaconda.users import cryptPassword, guess_username, check_groupname
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

from pyanaconda.core.regexes import GROUPLIST_FANCY_PARSE

from pyanaconda.anaconda_loggers import get_module_logger
log = get_module_logger(__name__)

__all__ = ["UserSpoke", "AdvancedUserDialog"]

class AdvancedUserDialog(GUIObject, GUIDialogInputCheckHandler):
    """
       .. inheritance-diagram:: AdvancedUserDialog
          :parts: 3
    """
    builderObjects = ["advancedUserDialog", "uid", "gid"]
    mainWidgetName = "advancedUserDialog"
    uiFile = "spokes/advanced_user.glade"

    def _validateGroups(self, inputcheck):
        groups_string = self.get_input(inputcheck.input_obj)

        # Pass if the string is empty
        if not groups_string:
            return InputCheck.CHECK_OK

        # Check each group name in the list
        for group in groups_string.split(","):
            group_name = GROUPLIST_FANCY_PARSE.match(group).group('name')
            valid, message = check_groupname(group_name)
            if not valid:
                return message or _("Invalid group name.")

        return InputCheck.CHECK_OK

    def __init__(self, user, data):
        GUIObject.__init__(self, data)

        saveButton = self.builder.get_object("save_button")
        GUIDialogInputCheckHandler.__init__(self, saveButton)

        self._user = user

        # Track whether the user has requested a home directory other
        # than the default. This way, if the home directory is left as
        # the default, the default will change if the username changes.
        # Otherwise, once the directory is set it stays that way.
        self._origHome = None

    def _grabObjects(self):
        self._cUid = self.builder.get_object("c_uid")
        self._cGid = self.builder.get_object("c_gid")
        self._tHome = self.builder.get_object("t_home")
        self._lHome = self.builder.get_object("l_home")
        self._tGroups = self.builder.get_object("t_groups")
        self._spinUid = self.builder.get_object("spin_uid")
        self._spinGid = self.builder.get_object("spin_gid")
        self._uid = self.builder.get_object("uid")
        self._gid = self.builder.get_object("gid")

    def initialize(self):
        GUIObject.initialize(self)

        self._grabObjects()

        # Validate the group input box
        self.add_check(self._tGroups, self._validateGroups)
        # Send ready signal to main event loop
        hubQ.send_ready(self.__class__.__name__, False)

    def refresh(self):
        if self._user.homedir:
            homedir = self._user.homedir
        elif self._user.name:
            homedir = "/home/" + self._user.name

        self._tHome.set_text(homedir)
        self._origHome = homedir

        self._cUid.set_active(bool(self._user.uid))
        self._cGid.set_active(bool(self._user.gid))

        self._spinUid.update()
        self._spinGid.update()

        self._tGroups.set_text(", ".join(self._user.groups))

    def apply(self):
        # Copy data from the UI back to the kickstart object
        homedir = self._tHome.get_text()

        # If the user cleared the home directory, revert back to the
        # default
        if not homedir:
            self._user.homedir = None
        # If the user modified the home directory input, save that the
        # home directory has been modified and use the value.
        elif self._origHome != homedir:
            if not os.path.isabs(homedir):
                homedir = "/" + homedir
            self._user.homedir = homedir

        # Otherwise leave the home directory alone. If the home
        # directory is currently the default value, the next call
        # to refresh() will update the input text to reflect
        # changes in the username.

        if self._cUid.get_active():
            self._user.uid = int(self._uid.get_value())
        else:
            self._user.uid = None

        if self._cGid.get_active():
            self._user.gid = int(self._gid.get_value())
        else:
            self._user.gid = None

        # ''.split(',') returns [''] instead of [], which is not what we want
        self._user.groups = [g.strip() for g in self._tGroups.get_text().split(",") if g]

        # Send ready signal to main event loop
        hubQ.send_ready(self.__class__.__name__, False)

    def run(self):
        self.window.show()
        while True:
            rc = self.window.run()

            #OK clicked
            if rc == 1:
                # Input checks pass
                if self.on_ok_clicked():
                    self.apply()
                    break
                # Input checks fail, try again
                else:
                    continue

            #Cancel clicked, window destroyed...
            else:
                break

        self.window.hide()
        return rc

    def on_uid_checkbox_toggled(self, togglebutton, data=None):
        # Set the UID spinner sensitivity based on the UID checkbox
        self._spinUid.set_sensitive(togglebutton.get_active())

    def on_gid_checkbox_toggled(self, togglebutton, data=None):
        # Same as above, for GID
        self._spinGid.set_sensitive(togglebutton.get_active())

    def on_uid_mnemonic_activate(self, widget, group_cycling, user_data=None):
        # If this is the only widget with the mnemonic (group_cycling is False),
        # and the checkbox is not currently toggled, toggle the checkbox and
        # then set the focus to the UID spinner
        if not group_cycling and not widget.get_active():
            widget.set_active(True)
            self._spinUid.grab_focus()
            return True

        # Otherwise just use the default signal handler
        return False

    def on_gid_mnemonic_activate(self, widget, group_cycling, user_data=None):
        # Same as above, but for GID
        if not group_cycling and not widget.get_active():
            widget.set_active(True)
            self._spinGid.grab_focus()
            return True

        return False

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
        if environment == constants.ANACONDA_ENVIRON:
            return True
        elif environment == constants.FIRSTBOOT_ENVIRON and data is None:
            # cannot decide, stay in the game and let another call with data
            # available (will come) decide
            return True
        elif environment == constants.FIRSTBOOT_ENVIRON and data and len(data.user.userList) == 0:
            return True
        else:
            return False

    def __init__(self, *args):
        NormalSpoke.__init__(self, *args)
        GUISpokeInputCheckHandler.__init__(self)

        self._users_module = USERS.get_observer()
        self._users_module.connect()

    def initialize(self):
        NormalSpoke.initialize(self)
        self.initialize_start()

        # Create a new UserData object to store this spoke's state
        # as well as the state of the advanced user dialog.
        if self.data.user.userList:
            self._user = copy.copy(self.data.user.userList[0])
        else:
            self._user = self.data.UserData()

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
        # regards both fields empty as success to let the user escape
        self._confirm_check.success_if_confirmation_empty = True
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

        # indicate when the password was set by kickstart
        self.password_kickstarted = self.data.user.seen

        # Modify the GUI based on the kickstart and policy information
        # This needs to happen after the input checks have been created, since
        # the Gtk signal handlers use the input check variables.
        password_set_message = _("The password was set by kickstart.")
        if self.password_kickstarted:
            self.password_entry.set_placeholder_text(password_set_message)
            self.password_confirmation_entry.set_placeholder_text(password_set_message)

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

    def refresh(self):
        self.username = self._user.name

        # rerun checks so that we have a correct status message, if any
        self.checker.run_checks()

    @property
    def status(self):
        if len(self.data.user.userList) == 0:
            return _("User creation is required")
        elif "wheel" in self.data.user.userList[0].groups:
            return _("Administrator %s will be created") % self.data.user.userList[0].name
        else:
            return _("User %s will be created") % self.data.user.userList[0].name

    @property
    def mandatory(self):
        return True

    def apply(self):
        # set the password only if the user enters anything to the text entry
        # this should preserve the kickstart based password
        if self.password:
            self.password_kickstarted = False
            self._user.password = cryptPassword(self.password)
            self._user.isCrypted = True
            self.remove_placeholder_texts()

        self._user.name = self.username

        if "wheel" not in self._user.groups:
            self._user.groups.append("wheel")
        if "qubes" not in self._user.groups:
            self._user.groups.append("qubes")

        # Copy the spoke data back to kickstart
        # If the user name is not set, no user will be created.
        if self._user.name:
            ksuser = copy.copy(self._user)
            if not self.data.user.userList:
                self.data.user.userList.append(ksuser)
            else:
                self.data.user.userList[0] = ksuser
        elif self.data.user.userList:
            self.data.user.userList.pop(0)

    @property
    def sensitive(self):
        # Spoke cannot be entered if a user was set in the kickstart and the user
        # policy doesn't allow changes.
        return not (self.completed and flags.automatedInstall
                    and self.data.user.seen and not self.checker.policy.changesok)

    @property
    def completed(self):
        return len(self.data.user.userList) > 0

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
        # without inputting any root password. Separate logic makes sure an
        # empty string is not unexpectedly set as the user password.
        if self.checker.success:
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
