/*
 * The MIT License
 * 
 * Copyright (c) 2004-2016, Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc., Seiji Sogabe, Tom Huybrechts, Jochen Fuerbacher
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.security;

import org.jenkinsci.plugins.matrixauth.Messages;

import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.core.JVM;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.mapper.Mapper;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.View;
import hudson.model.ViewProperty;
import hudson.security.ACL;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.util.RobustReflectionConverter;

public class ViewMatrixAuthorizationStrategy extends GlobalMatrixAuthorizationStrategy {
    
    @Override
    public ACL getACL(View view) {        
        for(ViewProperty prop : view.getProperties()){
            if(prop != null && prop instanceof ViewAuthorizationMatrixProperty){
                
                ViewAuthorizationMatrixProperty vamp = (ViewAuthorizationMatrixProperty) prop;
                SidACL viewAcl = vamp.getACL();
                
                if(vamp.isBlocksInheritance()){
                    return viewAcl;
                }
            }
        }
        return getRootACL();
    }
    
    @Extension
    public static final Descriptor<AuthorizationStrategy> DESCRIPTOR = new DescriptorImpl() {
        @Override
        protected GlobalMatrixAuthorizationStrategy create() {
            return new ViewMatrixAuthorizationStrategy();
        }

        @Override
        public String getDisplayName() {
            return Messages.ViewMatrixAuthorizationStrategy_DisplayName();
        }
    };

    public static class ConverterImpl extends GlobalMatrixAuthorizationStrategy.ConverterImpl {
        private RobustReflectionConverter ref;

        public ConverterImpl(Mapper m) {
            ref = new RobustReflectionConverter(m,new JVM().bestReflectionProvider());
        }

        @Override
        protected GlobalMatrixAuthorizationStrategy create() {
            return new ViewMatrixAuthorizationStrategy();
        }

        @Override
        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
            String name = reader.peekNextChild();
            if(name!=null && (name.equals("permission")))
                // the proper serialization form
                return super.unmarshal(reader, context);
            else
                // remain compatible with earlier problem where we used reflection converter
                return ref.unmarshal(reader,context);
        }

        @Override
        public boolean canConvert(Class type) {
            return type==ViewMatrixAuthorizationStrategy.class;
        }
    }
}
