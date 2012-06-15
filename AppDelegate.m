/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

//
//  AppDelegate.m
//  MyCordova
//
//  Created by Nagoor.KaniS on 5/30/12.
//  Copyright __MyCompanyName__ 2012. All rights reserved.
//

#import <CoreLocation/CoreLocation.h>
#import <CommonCrypto/CommonCryptor.h>

#import "AppDelegate.h"
#import "MainViewController.h"

#ifdef CORDOVA_FRAMEWORK
    #import <Cordova/CDVPlugin.h>
    #import <Cordova/CDVURLProtocol.h>
#else
    #import "CDVPlugin.h"
    #import "CDVURLProtocol.h"
#endif


@implementation AppDelegate

@synthesize window, webView, viewController;

- (id) init
{	
	/** If you need to do any extra app-specific initialization, you can do it here
	 *  -jm
	 **/
    NSHTTPCookieStorage *cookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage]; 
    [cookieStorage setCookieAcceptPolicy:NSHTTPCookieAcceptPolicyAlways];
        
    [CDVURLProtocol registerURLProtocol];
    
    return [super init];
}


#pragma UIApplicationDelegate implementation

/**
 * This is main kick off after the app inits, the views and Settings are setup here. (preferred - iOS4 and up)
 */
- (BOOL) application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions
{    
    NSURL* url = [launchOptions objectForKey:UIApplicationLaunchOptionsURLKey];
    NSString* invokeString = nil;
    
    if (url && [url isKindOfClass:[NSURL class]]) {
        invokeString = [url absoluteString];
		NSLog(@"MyCordova launchOptions = %@", url);
    }    
    
    CGRect screenBounds = [[UIScreen mainScreen] bounds];
    self.window = [[[UIWindow alloc] initWithFrame:screenBounds] autorelease];
    self.window.autoresizesSubviews = YES;
    
    CGRect viewBounds = [[UIScreen mainScreen] applicationFrame];
    
    self.viewController = [[[MainViewController alloc] init] autorelease];
    self.viewController.wwwFolderName = @"www";
    self.viewController.startPage = @"index.html";
    self.viewController.invokeString = invokeString;
    self.viewController.view.frame = viewBounds;
    
    self.webView.delegate = self;
    [self.window addSubview:self.viewController.view];
    
    NSURL *appURL = [NSURL URLWithString:@"index.html"];
    NSString* loadErr = nil;
    
//    NSString * _key = @"test123";
    NSString * _key = [self getKey];

    if (!loadErr) {
        NSString *js = [self DecryptFile:@"www/cordova-1.7.0" :@"js" :_key];
        NSString *html = [self DecryptFile:@"www/index" :@"html" :_key];
        
//        NSString *html = [self getDecryptHtml:_key];
        [self.webView loadHTMLString:html baseURL:appURL];
    } else {
        NSString* html = [NSString stringWithFormat:@"<html><body> %@ </body></html>", loadErr];
        [self.webView loadHTMLString:html baseURL:nil];
    }
    
    [self.window makeKeyAndVisible];
    return YES;    

}

- (NSString *) getDecryptHtml:(NSString *)key
{
    NSString *inputPath = [[NSBundle mainBundle] pathForResource:@"www/index" ofType:@"html"];
    NSData *dataIn = [NSData dataWithContentsOfFile:inputPath];

    if ( inputPath == NULL ) {
        NSLog(@"No file found...!");
        return nil;
    }
    
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [dataIn length];
    NSLog(@"Data length: %i", dataLength);
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *dataOut = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus result = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, keyPtr,kCCKeySizeAES256, NULL, [dataIn bytes], dataLength, dataOut, bufferSize, &numBytesEncrypted);    
    
    
    NSData *output_decrypt = [NSData dataWithBytesNoCopy:dataOut length:numBytesEncrypted];    
    
    NSString * html;

    NSLog(@"Encrypt bytes: %lu", numBytesEncrypted);       
    
    if (result == kCCSuccess && numBytesEncrypted != 0) {
        
        NSString * docsDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        NSString * outPath = [docsDir stringByAppendingPathComponent:@"index_des.html"];
        
        [output_decrypt writeToFile:inputPath atomically:YES];
        
        html = [[NSString alloc] initWithData:output_decrypt encoding:NSUTF8StringEncoding];
  
//        NSLog(@"Decrypted HTML code: %@", html);
    }
    if (html == nil) {
        html = [NSString stringWithFormat:@"<html><body>%@ file corrupted</body></html>", inputPath];
    }	
    return [html retain];    
//    return nil;
    
}


- (NSString *) DecryptFile :(NSString *)file :(NSString *)fmt :(NSString *)key
{
    
    NSString *inputPath = [[NSBundle mainBundle] pathForResource:file ofType:fmt];
    NSData *dataIn = [NSData dataWithContentsOfFile:inputPath];
    
    if ( inputPath == NULL ) {
        NSLog(@"No file found...!");
        return nil;
    }
    
    char keyPtr[kCCKeySizeAES256+1]; 
    bzero(keyPtr, sizeof(keyPtr)); 
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [dataIn length];

    NSLog(@"Data length: %i", dataLength);
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *dataOut = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus result = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, keyPtr,kCCKeySizeAES256, NULL, [dataIn bytes], dataLength, dataOut, bufferSize, &numBytesEncrypted);    
    
    
    NSData *output_decrypt = [NSData dataWithBytesNoCopy:dataOut length:numBytesEncrypted];    
    
    NSString * html;
    
    NSLog(@"Encrypt bytes: %lu", numBytesEncrypted);       
    
    if (result == kCCSuccess && numBytesEncrypted != 0) {
        [output_decrypt writeToFile:inputPath atomically:YES];
        html = [[NSString alloc] initWithData:output_decrypt encoding:NSUTF8StringEncoding];
    }
    if (html == nil) {
        html = [NSString stringWithFormat:@"<html><body>%@ file corrupted</body></html>", inputPath];
    }
    return [html retain];    
}


-(NSString *) getKey{

    NSString *key = [NSString stringWithContentsOfFile: @"Users/z062281/Desktop/keys.txt"];
    NSLog(@"File contents: %@", key);
    return key;
    
}


- (void) dealloc
{
	[super dealloc];
}

@end
