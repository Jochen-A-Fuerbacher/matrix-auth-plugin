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

import java.util.HashSet;
import java.util.Set;

import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.core.JVM;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.mapper.Mapper;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.View;
import hudson.model.ViewProperty;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.util.RobustReflectionConverter;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.Messages;

public class ViewMatrixAuthorizationStrategy extends GlobalMatrixAuthorizationStrategy {
   
    @Override
    public Set<String> getGroups() {
        System.out.println("getGroups() called.");
        Set<String> r = new HashSet<String>();
        r.addAll(super.getGroups());
        
        for(View view : Jenkins.getActiveInstance().getViews()){
            for(ViewProperty prop : view.getProperties()){
                if(prop!= null && prop instanceof ViewAuthorizationMatrixProperty){
                    r.addAll(((ViewAuthorizationMatrixProperty) prop).getGroups());
                }
            }
        }
        return r;
    }
    
    @Override
    public ACL getACL(View view) {
        for(ViewProperty prop : view.getProperties()){
            if(prop != null && prop instanceof ViewAuthorizationMatrixProperty){
                return ((ViewAuthorizationMatrixProperty) prop).getACL();
                
            }
        }
        return null;
    }

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
