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
