/*
 * Copyright (c) 2011 Roberto Tyley
 *
 * This file is part of 'Toy Android ssh-agent'.
 *
 * 'Toy Android ssh-agent' is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * 'Toy Android ssh-agent' is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with 'Toy Android ssh-agent'.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.madgag.ssh.toysshagent;

import java.util.List;

import roboguice.application.RoboApplication;

import com.google.inject.Module;

public class ToySshAgentApplication extends RoboApplication {
	protected void addApplicationModules(List<Module> modules) {
        modules.add(new ToySshAgentModule());
    }
}
