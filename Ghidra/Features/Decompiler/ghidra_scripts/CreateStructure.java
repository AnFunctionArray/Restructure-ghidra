/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Automatically creates a structure definition based on the references seen to the structure
//   To use this, place the cursor on a function parameter for example func(int *this),
//   (for a C++ this call function)
//   This script will automatically create a structure definition for the pointed at structure
//   and fill it out based on the references found by the decompiler.
//
//   If the parameter is already a structure pointer, any new references found will be added
//   to the structure, even if the structure must grow.
//
//   Eventually this WILL be put into a global type analyzer, but for now it is most useful.
//
//   This script assumes good flow, that switch stmts are good.
//
//   This script CAN be used in the decompiler by assigning a Binding a Keyboard key to it, then
//   placing the cursor on the variable in the decompiler that is a structure pointer (even if it
//   isn't one now, and then pressing the Quick key.
//
//@category Data Types
//@keybinding F6

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.actions.FillOutStructureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

public class CreateStructure extends GhidraScript {

	@Override
	public void run() throws Exception {
		/*println("" + currentLocation.toString());
		FillOutStructureCmd fillCmd =
				new FillOutStructureCmd(currentProgram, currentLocation, state.getTool());
		fillCmd.applyTo(currentProgram, this.monitor);*/
		FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
		DecompInterface decomp = setUpDecompiler(currentProgram);
		for (Function fn : funcs) {
			Variable[] allvars = fn.getAllVariables();
			for(Variable var : allvars) {
				/*DecompileResults res = decomp.decompileFunction(fn, 10000, monitor);
				ClangNode nodres = null;
				ClangTokenGroup ccode = res.getCCodeMarkup();
				println("Decompiled " + fn.getName());
				ClangToken tokeres = new ClangToken((ClangNode) var.getVariableStorage().getFirstVarnode());
				*/
				DataType dattyp = var.getDataType();
				String datatypstring = dattyp.getDisplayName();
				if(!datatypstring.contains("*")) continue;
				datatypstring = datatypstring.replaceAll("\\[|\\]|\\*|\\s", "");
		        //println(datatypstring = datatypstring.replaceAll("\\[|\\]|\\*|\\s", ""));
		        DecompileResults res = decomp.decompileFunction(fn, 10000, monitor);
		        
		        //println("type : " + dattyp.getCategoryPath().getName());
		        
		        if(!dattyp.getCategoryPath().getName().equals("Demangler")) {
		        	continue;
		        }
		        
		        ClangTokenGroup tokengrp = res.getCCodeMarkup();
		        
		        if(tokengrp == null) continue;
		        
		        ClangToken tokeres = null;
		        
		        //println("searching for " + datatypstring);
		        
		        mainloop:
		        for(ClangNode  token : tokengrp) {
		        	if(token instanceof ClangFuncProto) {
		        		for(ClangNode  outter : ((ClangFuncProto)token)) {
		        			if(outter instanceof ClangVariableDecl)
		        			for(ClangNode inner2 : ((ClangVariableDecl)outter)) {
			        			if(inner2 instanceof ClangToken) {
			        				if(((ClangToken)inner2).getText().equals(datatypstring)) {
						        		tokeres = (ClangToken)inner2;
						        		//println(inner2.getClass().toString());
						        		break mainloop;
						        	}
				        			else {
				        				//println("" + ((ClangToken)inner2).getText());
				        			}
			        			}
			        			else {
			        				//println(inner2.getClass().toString());
			        			}
		        			}
		        	}
		        }
		        }
		        if(tokeres == null) continue;
		        //println("found");
		        
				//ClangToken tokeres = new ClangToken(null, datatypstring);
				DecompilerLocation loc = new DecompilerLocation(currentProgram, fn.getEntryPoint(), fn.getEntryPoint(), res, tokeres,1,1);
				println("" + loc);
				FillOutStructureCmd fillCmd =
						new FillOutStructureCmd(currentProgram, loc, state.getTool());
				fillCmd.applyTo(currentProgram, this.monitor);
			}
		}
	}
	
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		// call it to get results
		if (!decompInterface.openProgram(currentProgram)) {
			println("Decompile Error: " + decompInterface.getLastMessage());
			return null;
		}

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, program);
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}
}
