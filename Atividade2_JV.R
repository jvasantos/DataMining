library(corrplot)
library(ggplot2)
library(reshape2)
library(caret)
library(dplyr)
library(randomForest)
library(gmodels)
library(e1071)
library(irr)
library(C50)
library(caret)
library(RWeka)



glibc_unb <- read.csv(file.choose(), stringsAsFactors = TRUE)
glibc_bal <- read.csv(file.choose(), stringsAsFactors = TRUE)

glibc_unb <- glibc_unb[-29]
glibc_bal <- glibc_bal[-29]

httpd_unb <- read.csv(file.choose(), stringsAsFactors = TRUE)
httpd_bal <- read.csv(file.choose(), stringsAsFactors = TRUE)

httpd_unb <- httpd_unb[-29]
httpd_bal <- httpd_bal[-29]

kernel_unb <- read.csv(file.choose(), stringsAsFactors = TRUE)
kernel_bal <- read.csv(file.choose(), stringsAsFactors = TRUE)

kernel_unb <- kernel_unb[-29]
kernel_bal <- kernel_bal[-29]

mozilla_unb <- read.csv(file.choose(), stringsAsFactors = TRUE)
mozilla_bal <- read.csv(file.choose(), stringsAsFactors = TRUE)

mozilla_unb <- mozilla_unb[-29]
mozilla_bal <- mozilla_bal[-29]

xen_unb <- read.csv(file.choose(), stringsAsFactors = TRUE)
xen_bal <- read.csv(file.choose(), stringsAsFactors = TRUE)

xen_unb <- xen_unb[-29]
xen_bal <- xen_bal[-29]

################################## Pergunta 1 ##############################################
#Are there correlations among software metrics?
  
corr_matrix <- function(dataset){
  dataset <- dataset[-28]
  corr <- cor(dataset)
  corrplot(corr, type = "upper", order = "original", tl.col = "black", tl.cex = .6)
  print(findCorrelation(corr, cutoff = 0.9, verbose = TRUE, names = TRUE))
}

corr_matrix(glibc_unb)
corr_matrix(glibc_bal)

corr_matrix(httpd_unb)
corr_matrix(httpd_bal)

corr_matrix(kernel_unb)
corr_matrix(kernel_bal)

corr_matrix(mozilla_unb)
corr_matrix(mozilla_bal)

corr_matrix(xen_unb)
corr_matrix(xen_bal)

#################################### Pergunta 2 #####################################
#Are the software metrics able to represent functions with reported vulnerabilities?

importance_plot <- function(dataset){
  df.m <- melt(dataset, id.var = "Affected")
  
  results <- ggplot(data = df.m, aes(x=variable, y=value)) + geom_boxplot(aes(fill=Affected)) + 
    facet_wrap(~ variable, scales = "free", shrink = TRUE) + scale_y_continuous(limits=c(0,150))
  return(results)  
}

print(importance(httpd_unb))

#ggplot(glibc_bal, aes(y = CountLineCodeDecl, x = Affected)) + geom_boxplot(aes(fill=Affected))

importance_order <- function(dataset){
  control <- trainControl(method="repeatedcv", number=10, repeats=3)
  model <- train(Affected~., data=dataset, method="lvq", preProcess="scale", trControl=control)
  importance <- varImp(model, scale=FALSE)
  print(importance)
  plot(importance)
  
}

#importance_order(glibc_unb)
importance_order(glibc_bal)

#importance_order(httpd_unb)
importance_order(httpd_bal)

#importance_order(kernel_unb)
importance_order(kernel_bal)

importance_order(xen_bal)
  
statistic_test <- function(dataset){
  df.m <- melt(dataset, id.var = "Affected")
  dataset <- dataset[-28]
  for (i in names(dataset)) {
    print(i)
    sig <- subset(df.m, variable == i)
    wilcox_res <- wilcox.test(value ~ Affected, data= sig, paired = FALSE)
    print(wilcox_res)
    t_res <- t.test(value ~ Affected, data= sig, paired = FALSE)
    print(t_res)
  }
}

statistic_test(glibc_bal)
statistic_test(glibc_unb)

statistic_test(httpd_bal)
statistic_test(httpd_unb)

statistic_test(kernel_bal)
statistic_test(kernel_unb)

statistic_test(xen_bal)
statistic_test(xen_unb) #Crash!!

statistic_test(mozilla_bal)
statistic_test(mozilla_unb) #Slow!!

hist(glibc_unb$Cyclomatic, xlim = c(0,15000), ylim = c(0,100), breaks = 400)
hist(glibc_bal$Cyclomatic, breaks = 5)

ggplot(data = mozilla_bal, aes(y = Knots, x = Affected)) + geom_boxplot(aes(fill=Affected)) +
  scale_y_continuous(limits=c(0,10))
ggplot(data = mozilla_unb, aes(y = Knots, x = Affected)) + geom_boxplot(aes(fill=Affected)) +
  scale_y_continuous(limits=c(0,10))

#################################### Pergunta 3 #####################################
#How effective are machine learning techniques to predict vulnerable functions?

# Precision
precision <- function(tp, fp){
  
  precision <- tp/(tp+fp)
  
  return(precision)
}

# Recall
recall <- function(tp, fn){
  
  recall <- tp/(tp+fn)
  
  return(recall)
}

# F-measure
f_measure <- function(tp, fp, fn){
  
  f_measure <- (2*precision(tp,fp)*recall(tp,fn))/(recall(tp,fn) + precision(tp, fp))
  
  return(f_measure)
}

informedness <- function(tp, fn, tn, fp){
  
  tpr <- recall(tp, fn)
  tnr <- tn/(tn+fp)
  informedness <- tpr+tnr-1
  
  return(informedness)
}

markedness <- function(tp, fp, tn, fn){
  
  ppv <- precision(tp,fp)
  npv <- tn/(tn+fn)
  mk <- ppv+npv-1
  
  return(mk)
}

normalize <- function(x) {
  return ((x - min(x))/(max(x) - min(x)))
}



##############CARET######################
#KNN
callKNN <- function(dataset) {
  set.seed(2022)
  intrain <- createDataPartition(y = dataset$Affected, p = 0.7, list = FALSE)
  training <- dataset[intrain,]
  testing <- dataset[-intrain,]
  trctrl <- trainControl(method = "repeatedcv", number = 10, repeats = 3)
  
  knn_fit <- train(Affected ~., data = training, method = "knn",
                   trControl=trctrl,
                   preProcess = c("center", "scale"),
                   tuneLength = 10)
  
  teste_pred <- predict(knn_fit, newdata = testing)
  results <- confusionMatrix(teste_pred, testing$Affected, mode = "everything")
  return(results)
}

#Naive Bayes
callBayes <- function(dataset){
  intrain <- createDataPartition(y = dataset$Affected, p = 0.7, list = FALSE)
  training <- dataset[intrain,]
  testing <- dataset[-intrain,]
  trctrl <- trainControl(method = "repeatedcv", number = 10, repeats = 3)
  
  nb_model <- train(Affected ~., data = training, method = "nb",
                    trControl=trctrl,
                    preProcess = c("center", "scale"),
                    tuneLength = 10, prox = TRUE, allowParallel = TRUE)
  
  nb_pred <- predict(nb_model, newdata = testing)
  results <- confusionMatrix(nb_pred, testing$Affected, mode = "everything")
  return(results)
}

#Random Forest
callRF <- function(dataset){
  set.seed(2022)
  intrain <- createDataPartition(y = dataset$Affected, p = 0.7, list = FALSE)
  training <- dataset[intrain,]
  testing <- dataset[-intrain,]
  trctrl <- trainControl(method = "repeatedcv", number = 10, repeats = 3)
  
  rf_model <- train(Affected ~., data = training, method = "rf",
                    trControl=trctrl,
                    preProcess = c("center", "scale"),
                    tuneLength = 10, prox = TRUE, allowParallel = TRUE)
  print(rf_model$finalModel)
  
  rf_pred <- predict(rf_model, newdata = testing)
  results <- confusionMatrix(rf_pred, testing$Affected, mode = "everything")
  return(results)
}

#SVM
callSVM <- function(dataset){
  set.seed(2022)
  intrain <- createDataPartition(y = dataset$Affected, p = 0.7, list = FALSE)
  training <- dataset[intrain,]
  testing <- dataset[-intrain,]
  trctrl <- trainControl(method = "repeatedcv", number = 10, repeats = 3)
  
  SVMgrid <- expand.grid(sigma = c(0.0577), C = c(2.21049))
  modelSvmRRB <- train(Affected ~., data = training, method="svmRadial",
                       trControl=trctrl,tuneGrid = SVMgrid, 
                       preProc = c("scale","center"), verbose=FALSE)
  
  svm_pred <- predict(modelSvmRRB, newdata = testing)
  results <- confusionMatrix(svm_pred, testing$Affected, mode = "everything")
  
}

result <- callBayes(glibc_unb) #Done
result
result <- callRF(httpd_bal) #Done
result <- callKNN(httpd_bal) #Done
result <- callBayes(httpd_bal) #Done
result <- callSVM(httpd_bal) #Done

result <- callBayes(httpd_unb) #Done
result <- callSVM(httpd_unb) #Done
result

result <- callRF(xen_bal) #Done
result
result <- callKNN(xen_bal) #Done
result
result <- callBayes(xen_bal) #Done
result
result <- callSVM(xen_bal) #Done
result

result <- callBayes(xen_unb) #Done
result
result <- callSVM(xen_unb) #Crash: não é poss�???vel alocar vetor de tamanho 3.5 Gb

mozilla_bal_KNN_res <- callKNN(mozilla_bal)
mozilla_bal_KNN_res
mozilla_bal_Bayes_res <- callBayes(mozilla_bal)
mozilla_bal_Bayes_res
mozilla_bal_SVM_res <- callSVM(mozilla_bal)
mozilla_bal_SVM_res

mozilla_unb_Bayes_res <- callBayes(mozilla_unb)



#######################FUNCTIONS##################
executeNaiveBayes <- function(dataset, folds){
  results <- lapply(folds, function(x) {
    train <- dataset[-x, ]
    test <- dataset[x, ]
    model <- naiveBayes(train, train$Affected, laplace = 1)
    pred <- predict(model, test)
    
    results <- measures(test$Affected, pred)
    
    return(results)
  })
  
}

executeRandomForest <- function(dataset, folds){
  results <- lapply(folds, function(x) {
    train <- dataset[-x, ]
    test <- dataset[x, ]
    model <- randomForest(train$Affected~ ., data = train)
    pred <- predict(model, test)
    
    results <- measures(test$Affected, pred)
    
    return(results)
  })
}

executeSVM <- function(dataset, folds){
  results <- lapply(folds, function(x) {
    train <- dataset[-x, ]
    test <- dataset[x, ]
    model <- svm(train$Affected~ ., data = train)
    pred <- predict(model, test)
    
    results <- measures(test$Affected, pred)
    
    return(results)
  })
  
}

measures <- function(test, pred){
  
  true_positive <- 0
  true_negative <- 0
  false_positive <- 0
  false_negative <- 0
  
  for(i in 1:length(pred)){
    if(test[i] == "VULNERABLE" && pred[i] == "VULNERABLE"){
      true_positive <- true_positive + 1
    }else if(test[i] == "NEUTRAL" && pred[i] == "NEUTRAL"){
      true_negative <- true_negative + 1
    }else if(test[i] == "NEUTRAL" && pred[i] == "VULNERABLE"){
      false_negative <- false_negative + 1
    }else if(test[i] == "VULNERABLE" && pred[i] == "NEUTRAL"){
      false_positive <- false_positive + 1
    }
  }
  
  measures <- c(precision(true_positive,false_positive), 
                recall(true_positive,false_negative), 
                f_measure(true_positive,false_positive,false_negative),
                informedness(true_positive,false_negative,true_negative,false_positive),
                markedness(true_positive,false_positive,true_negative,false_negative))
  
  return(measures)
}


####MOZILLA BALANCED
set.seed(3)
#Normalize
mozilla_bal[1:27] <- lapply(mozilla_bal[1:27], normalize)
#Factor
mozilla_bal$Affected <- factor(mozilla_bal$Affected)
#Folds
folds <- createFolds(mozilla_bal$Affected, k = 10)
#Random Forest
mozilla_bal_resultsR <- executeRandomForest(mozilla_bal, folds)
partial_results <- rowMeans(as.data.frame(mozilla_bal_resultsR), na.rm = TRUE)

####MOZILLA UNBALANCED
mozilla_unb[1:27] <- lapply(mozilla_unb[1:27], normalize)
#Factor
mozilla_unb$Affected <- factor(mozilla_unb$Affected)
#Folds
folds <- createFolds(mozilla_unb$Affected, k = 10)
#Naive Bayes
mozilla_unb_resultsNaiveBayes <- executeNaiveBayes(mozilla_unb, folds)
moz_unb_bayes_partial_results <- rowMeans(as.data.frame(resultsNaiveBayes), na.rm = TRUE)
#Random Forest
mozilla_unb_resultsRF <- executeRandomForest(mozilla_unb, folds) #Error: cannot allocate vector of size 5.7 Gb 
moz_unb_RF_partial_results <- rowMeans(as.data.frame(mozilla_unb_resultsRF), na.rm = TRUE)
#SVM
mozilla_unb_resultsSVM <- executeSVM(mozilla_unb, folds)
moz_unb_SVM_partial_results <- rowMeans(as.data.frame(mozilla_unb_resultsSVM), na.rm = TRUE)

###KERNEL BALANCED
kernel_bal[1:27] <- lapply(kernel_bal[1:27], normalize)
#Factor
kernel_bal$Affected <- factor(kernel_bal$Affected)
#Folds
folds <- createFolds(kernel_bal$Affected, k = 10)
#Naive Bayes
resultsNaiveBayes <- executeNaiveBayes(kernel_bal, folds)
kernel_bal_bayes_partial_results <- rowMeans(as.data.frame(resultsNaiveBayes), na.rm = TRUE)
#Random Forest
kernel_bal_resultsRF <- executeRandomForest(kernel_bal, folds)
kernel_bal_RF_partial_results <- rowMeans(as.data.frame(kernel_bal_resultsRF), na.rm = TRUE)
#SVM
kernel_bal_resultsSVM <- executeSVM(kernel_bal, folds)
kernel_bal_SVM_partial_results <- rowMeans(as.data.frame(kernel_bal_resultsSVM), na.rm = TRUE)

###GLIBC UNBALANCED
glibc_unb[1:27] <- lapply(glibc_unb[1:27], normalize)
#Factor
glibc_unb$Affected <- factor(glibc_unb$Affected)
#Folds
folds <- createFolds(glibc_unb$Affected, k = 10)
#Random Forest
glibc_unb_resultsRF <- executeRandomForest(glibc_unb, folds)
glibc_unb_RF_partial_results <- rowMeans(as.data.frame(glibc_unb_resultsRF), na.rm = TRUE)
#SVM
glibc_unb_resultsSVM <- executeSVM(glibc_unb, folds)
glibc_unb_SVM_partial_results <- rowMeans(as.data.frame(glibc_unb_resultsSVM), na.rm = TRUE)

###GLIBC BALANCED
glibc_bal[1:27] <- lapply(glibc_bal[1:27], normalize)
#Factor
glibc_bal$Affected <- factor(glibc_bal$Affected)
#Folds
folds <- createFolds(glibc_bal$Affected, k = 10)
#Naive Bayes
glibc_bal_resultsNaiveBayes <- executeNaiveBayes(glibc_bal, folds)
glibc_bal_bayes_partial_results <- rowMeans(as.data.frame(glibc_bal_resultsNaiveBayes), na.rm = TRUE)
#Random Forest
glibc_bal_resultsRF <- executeRandomForest(glibc_bal, folds)
glibc_bal_RF_partial_results <- rowMeans(as.data.frame(glibc_bal_resultsRF), na.rm = TRUE)
#SVM
glibc_bal_resultsSVM <- executeSVM(glibc_bal, folds)
glibc_bal_SVM_partial_results <- rowMeans(as.data.frame(glibc_bal_resultsSVM), na.rm = TRUE)

###HTTPD UNBALANCED
httpd_unb[1:27] <- lapply(httpd_unb[1:27], normalize)
#Factor
httpd_unb$Affected <- factor(httpd_unb$Affected)
#Folds
folds <- createFolds(httpd_unb$Affected, k = 10)
#Random Forest
httpd_unb_resultsRF <- executeRandomForest(httpd_unb, folds)
httpd_unb_RF_partial_results <- rowMeans(as.data.frame(httpd_unb_resultsRF), na.rm = TRUE)

###XEN UNBALANCED
xen_unb[1:27] <- lapply(xen_unb[1:27], normalize)
#Factor
xen_unb$Affected <- factor(xen_unb$Affected)
#Folds
folds <- createFolds(xen_unb$Affected, k = 10)
#Random Forest
xen_unb_resultsRF <- executeRandomForest(xen_unb, folds)
xen_unb_RF_partial_results <- rowMeans(as.data.frame(xen_unb_resultsRF), na.rm = TRUE)
#SVM
xen_unb_resultsSVM <- executeSVM(xen_unb, folds)
xen_unb_SVM_partial_results <- rowMeans(as.data.frame(xen_unb_resultsSVM), na.rm = TRUE)

